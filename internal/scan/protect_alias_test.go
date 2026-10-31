package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hidetzu/reelwarden/internal/filesystem"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
)

// A protected subdirectory bind-mounted elsewhere in the root (or reached
// through another letter case or Unicode form) is the same directory under
// another path. The alias sorts first, so the protected path itself is
// skipped as a directory cycle; protection must still follow the file.
func TestProtectionFollowsIdentityThroughAliases(t *testing.T) {
	dir := scan.RealTempDir(t)
	alias := filepath.Join(dir, "a_mirror")
	sub := filepath.Join(dir, "z_keep", "sub")
	for _, p := range []string{filepath.Join(alias, "x.mp4"), filepath.Join(sub, "x.mp4"), filepath.Join(dir, "z_keep", "other.mp4")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("archive copy"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	same := map[string]model.FileIdentity{
		alias:                         {Device: 1, Inode: 500},
		sub:                           {Device: 1, Inode: 500},
		filepath.Join(alias, "x.mp4"): {Device: 1, Inode: 501},
		filepath.Join(sub, "x.mp4"):   {Device: 1, Inode: 501},
	}
	restore := scan.SetPlatform(
		func(p string, info os.FileInfo) filesystem.Identity {
			if id, ok := same[p]; ok {
				return filesystem.Identity{ID: id, Nlink: 1, Known: true, NlinkKnown: true}
			}
			return filesystem.IdentityOf(p, info)
		},
		func(string) filesystem.RootInfo {
			return filesystem.RootInfo{Filesystem: "ext4", Confidence: model.ConfidenceHigh}
		},
	)
	defer restore()

	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{dir}, ProtectRoots: []string{filepath.Join(dir, "z_keep")}})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range inv.Files {
		if f.PrimaryPath() == filepath.Join(alias, "x.mp4") {
			found = true
			if !f.Protected {
				t.Fatalf("file reached through an alias of a protected directory is unprotected: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("alias path not scanned: %+v", inv.Files)
	}
}

// A link whose target path lies outside the roots can still reach a scanned
// file through another spelling of its path (the root bind-mounted
// elsewhere, another letter case). The reference must follow identity.
func TestLinkThroughOutsideAliasKeepsReference(t *testing.T) {
	base := scan.RealTempDir(t)
	root := filepath.Join(base, "R")
	inRoot := filepath.Join(root, "e", "target.mp4")
	alias := filepath.Join(base, "alias", "e", "target.mp4") // what the bind mount would show
	for _, p := range []string{inRoot, alias} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("same file"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "x", "ref.mp4")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alias, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	same := model.FileIdentity{Device: 7, Inode: 4242}
	restore := scan.SetPlatform(
		func(p string, info os.FileInfo) filesystem.Identity {
			if p == inRoot || p == alias {
				return filesystem.Identity{ID: same, Nlink: 1, Known: true, NlinkKnown: true}
			}
			return filesystem.IdentityOf(p, info)
		},
		func(string) filesystem.RootInfo {
			return filesystem.RootInfo{Filesystem: "ext4", Confidence: model.ConfidenceHigh}
		},
	)
	defer restore()
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.PrimaryPath() == inRoot {
			if len(f.SymlinkRefs) != 1 {
				t.Fatalf("link through an outside alias not counted: %+v", f)
			}
			return
		}
	}
	t.Fatal("target not scanned")
}

// A recycle bin bind-mounted under an innocent name (Docker:
// -v .../#recycle:/data/deleted) is recognised by its mount source.
func TestBindMountedBinIsRecognised(t *testing.T) {
	base := scan.RealTempDir(t)
	write := func(p string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("same"), 0o644)
	}
	write(filepath.Join(base, "lib", "live", "movie.mkv"))
	write(filepath.Join(base, "lib", "view", "movie.mkv"))
	restore := scan.SetMounts(map[string]string{filepath.Join(base, "lib", "view"): "/volume1/#recycle"})
	defer restore()
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{filepath.Join(base, "lib")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 1 || inv.Files[0].PrimaryPath() != filepath.Join(base, "lib", "live", "movie.mkv") {
		t.Fatalf("bind-mounted bin was scanned: %+v", inv.Files)
	}
}

// A single file bind-mounted from a bin is neither scanned nor protecting.
func TestFileBindMountedFromBin(t *testing.T) {
	base := scan.RealTempDir(t)
	lib := filepath.Join(base, "lib")
	p := filepath.Join(lib, "a.mp4")
	os.MkdirAll(lib, 0o755)
	os.WriteFile(p, []byte("bin data"), 0o644)
	restore := scan.SetMounts(map[string]string{p: "/volume1/#recycle/a.mp4"})
	defer restore()
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{base}, ProtectRoots: []string{lib}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 0 {
		t.Fatalf("file bind-mounted from a bin was scanned: %+v", inv.Files)
	}
}

// Through a followed link the walk path hides that a folder is a bind mount
// of a bin; files are judged at their real path.
func TestFollowedLinkIntoBinMountIsNotProtected(t *testing.T) {
	base := scan.RealTempDir(t)
	real := filepath.Join(base, "scan", "real")
	k := filepath.Join(real, "bin", "K.mp4")
	os.MkdirAll(filepath.Dir(k), 0o755)
	os.WriteFile(k, []byte("X"), 0o644)
	os.MkdirAll(filepath.Join(base, "scan", "other"), 0o755)
	os.WriteFile(filepath.Join(base, "scan", "other", "C.mp4"), []byte("X"), 0o644)
	if err := os.Symlink("real", filepath.Join(base, "scan", "lnk")); err != nil {
		t.Skip(err)
	}
	restore := scan.SetMounts(map[string]string{filepath.Join(real, "bin"): "/vol/#recycle"})
	defer restore()
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{filepath.Join(base, "scan")}, ProtectRoots: []string{real}, FollowSymlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.Protected {
			t.Fatalf("a file in a bind-mounted bin became protected: %+v", f.KnownPaths)
		}
	}
}

// Nested or aliased protect roots all count as used.
func TestNestedProtectRootsAllMatch(t *testing.T) {
	base := scan.RealTempDir(t)
	lib := filepath.Join(base, "Lib")
	os.MkdirAll(filepath.Join(lib, "Sub"), 0o755)
	os.WriteFile(filepath.Join(lib, "Sub", "b.mp4"), []byte("b"), 0o644)
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{base}, ProtectRoots: []string{lib, filepath.Join(lib, "Sub")}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Failures != 0 {
		t.Fatalf("nested protect root reported as protecting nothing: %+v", inv.Warnings)
	}
}

// A hard link in @eaDir or a hidden folder of the library does not make an
// outside file protected; those folders are often deleted wholesale.
func TestMetadataFolderLinkDoesNotProtect(t *testing.T) {
	base := scan.RealTempDir(t)
	old := filepath.Join(base, "Old", "c.mp4")
	os.MkdirAll(filepath.Dir(old), 0o755)
	os.WriteFile(old, []byte("c"), 0o644)
	for _, d := range []string{"@eaDir", ".hidden"} {
		p := filepath.Join(base, "Lib", d, "c.mp4")
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Link(old, p); err != nil {
			t.Skip(err)
		}
	}
	os.WriteFile(filepath.Join(base, "Lib", "other.mp4"), []byte("o"), 0o644)
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{base}, ProtectRoots: []string{filepath.Join(base, "Lib")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.PrimaryPath() == old && f.InProtectedLibrary {
			t.Fatal("trusted keeper through a link in a metadata or hidden folder")
		}
	}
}

// Only files the walk reads as videos inside the protected root are trusted
// keepers: not hard links of hidden or non-video files, not files of an
// excluded folder (by root-relative pattern, also through a followed link),
// not a hidden protected root.
func TestOnlyScannedLibraryFilesAreTrustedKeepers(t *testing.T) {
	mk := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o644)
	}
	ln := func(old, new string) {
		os.MkdirAll(filepath.Dir(new), 0o755)
		if err := os.Link(old, new); err != nil {
			t.Skip(err)
		}
	}
	cases := map[string]func(r string) scan.Options{
		"excluded by root-relative pattern": func(r string) scan.Options {
			mk(filepath.Join(r, "lib", "ToDelete", "a.mp4"), "a")
			ln(filepath.Join(r, "lib", "ToDelete", "a.mp4"), filepath.Join(r, "other", "a.mp4"))
			return scan.Options{ProtectRoots: []string{filepath.Join(r, "lib")}, Excludes: []string{"lib/ToDelete"}}
		},
		"excluded, reached through a followed link": func(r string) scan.Options {
			mk(filepath.Join(r, "lib", "ToDelete", "a.mp4"), "a")
			os.MkdirAll(filepath.Join(r, "A"), 0o755)
			os.Symlink("../lib", filepath.Join(r, "A", "lnk"))
			return scan.Options{ProtectRoots: []string{filepath.Join(r, "lib")}, Excludes: []string{"lib/ToDelete"}, FollowSymlinks: true}
		},
		"hidden file in the library": func(r string) scan.Options {
			mk(filepath.Join(r, "lib", ".a.mp4"), "a")
			ln(filepath.Join(r, "lib", ".a.mp4"), filepath.Join(r, "other", "a.mp4"))
			return scan.Options{ProtectRoots: []string{filepath.Join(r, "lib")}}
		},
		"non-video file in the library": func(r string) scan.Options {
			mk(filepath.Join(r, "lib", "a.mp4.part"), "a")
			ln(filepath.Join(r, "lib", "a.mp4.part"), filepath.Join(r, "other", "a.mp4"))
			return scan.Options{ProtectRoots: []string{filepath.Join(r, "lib")}}
		},
		"hidden protected root": func(r string) scan.Options {
			mk(filepath.Join(r, ".lib", "a.mp4"), "a")
			ln(filepath.Join(r, ".lib", "a.mp4"), filepath.Join(r, "other", "a.mp4"))
			return scan.Options{ProtectRoots: []string{filepath.Join(r, ".lib")}}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := scan.RealTempDir(t)
			opts := setup(r)
			mk(filepath.Join(r, "dup", "a.mp4"), "a")
			opts.Roots = []string{r}
			inv, err := scan.Walk(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range inv.Files {
				if f.InProtectedLibrary {
					t.Fatalf("trusted keeper outside the scanned library: %v", f.KnownPaths)
				}
			}
		})
	}
}

// A directory link inside the library shields what it shows, so the file
// behind it is never proposed against another library copy.
func TestShieldFollowsDirectoryLinksInLibrary(t *testing.T) {
	base := scan.RealTempDir(t)
	os.MkdirAll(filepath.Join(base, "p"), 0o755)
	os.MkdirAll(filepath.Join(base, "old", "movies"), 0o755)
	os.WriteFile(filepath.Join(base, "p", "x.mp4"), []byte("v"), 0o644)
	os.WriteFile(filepath.Join(base, "old", "movies", "x.mp4"), []byte("v"), 0o644)
	if err := os.Symlink("../old/movies", filepath.Join(base, "p", "movies")); err != nil {
		t.Skip(err)
	}
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{base}, ProtectRoots: []string{filepath.Join(base, "p")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.PrimaryPath() == filepath.Join(base, "old", "movies", "x.mp4") && !f.Protected {
			t.Fatal("file shown in the library through a directory link is not shielded")
		}
	}
}

// Hidden, metadata or excluded folders do not become trusted library
// folders when bind-mounted into it or scanned as an explicit root.
func TestTrustNeedsCleanLibraryPath(t *testing.T) {
	base := scan.RealTempDir(t)
	mk := func(p string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("a"), 0o644)
	}
	view := filepath.Join(base, "P", "view")
	mk(filepath.Join(view, "a.mp4"))
	mk(filepath.Join(base, "P", ".stash", "b.mp4"))
	mk(filepath.Join(base, "P", "legit.mp4"))
	restore := scan.SetMounts(map[string]string{view: "/X/.hidden"})
	defer restore()
	var files []model.PhysicalFile
	for _, roots := range [][]string{{filepath.Join(base, "P")}, {filepath.Join(base, "P", ".stash")}} {
		inv, err := scan.Walk(context.Background(), scan.Options{Roots: roots, ProtectRoots: []string{filepath.Join(base, "P")}})
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, inv.Files...)
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[filepath.Base(f.PrimaryPath())] = true
		trusted := f.InProtectedLibrary
		switch filepath.Base(f.PrimaryPath()) {
		case "legit.mp4":
			if !trusted {
				t.Error("ordinary library file not trusted")
			}
		default:
			if trusted {
				t.Errorf("trusted through a hidden source: %v", f.KnownPaths)
			}
		}
	}
	if !seen["a.mp4"] || !seen["b.mp4"] {
		t.Fatalf("scenario not exercised: %v", seen)
	}
}

func TestTrustRejectsMountTricks(t *testing.T) {
	mk := func(p string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("a"), 0o644)
	}
	cases := map[string]func(base string) (map[string][]string, []string){
		// A library folder that is also mounted inside a bin.
		"reverse bind into a bin": func(base string) (map[string][]string, []string) {
			return map[string][]string{"/vol/Old/#recycle": {"/x", filepath.Join(base, "Lib", "sub")}}, nil
		},
		// A single file bind-mounted from a hidden folder.
		"single file from a hidden folder": func(base string) (map[string][]string, []string) {
			return map[string][]string{filepath.Join(base, "Lib", "sub", "a.mp4"): {"/X/.hid/a.mp4"}}, nil
		},
		// A folder excluded by a path pattern, bind-mounted into the library.
		"folder excluded by a path pattern": func(base string) (map[string][]string, []string) {
			return map[string][]string{filepath.Join(base, "Lib", "sub"): {"/Lib/a/excl"}}, []string{"a/ex*"}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			base := scan.RealTempDir(t)
			mk(filepath.Join(base, "Lib", "sub", "a.mp4"))
			mk(filepath.Join(base, "Lib", "own.mp4"))
			table, excl := setup(base)
			restore := scan.SetMountTable(table)
			defer restore()
			inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{filepath.Join(base, "Lib")}, ProtectRoots: []string{filepath.Join(base, "Lib")}, Excludes: excl})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range inv.Files {
				if filepath.Base(f.PrimaryPath()) == "a.mp4" && f.InProtectedLibrary {
					t.Fatalf("trusted despite %s", name)
				}
				if filepath.Base(f.PrimaryPath()) == "own.mp4" && !f.InProtectedLibrary {
					t.Fatal("ordinary library file lost trust")
				}
			}
		})
	}
}

// The shield does not wander outside the scan: a library link to /etc
// must not turn into unreadable-folder failures.
func TestShieldStaysInScope(t *testing.T) {
	base := scan.RealTempDir(t)
	lib := filepath.Join(base, "lib")
	os.MkdirAll(lib, 0o755)
	os.WriteFile(filepath.Join(lib, "a.mp4"), []byte("a"), 0o644)
	if err := os.Symlink("/etc", filepath.Join(lib, "etclink")); err != nil {
		t.Skip(err)
	}
	inv, err := scan.Walk(context.Background(), scan.Options{Roots: []string{base}, ProtectRoots: []string{lib}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Failures != 0 {
		t.Fatalf("shield walked outside the scan: %+v", inv.Warnings)
	}
}

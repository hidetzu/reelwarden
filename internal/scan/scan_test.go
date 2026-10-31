package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
)

func write(t *testing.T, p string, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, old, new string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(new), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(old, new); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
}

func symlink(t *testing.T, target, new string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(new), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, new); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
}

func fileByPath(inv *Inventory, p string) *model.PhysicalFile {
	for i := range inv.Files {
		for _, kp := range inv.Files[i].KnownPaths {
			if kp == p {
				return &inv.Files[i]
			}
		}
	}
	return nil
}

func entryByPath(inv *Inventory, p string) *model.PathEntry {
	for i := range inv.Entries {
		if inv.Entries[i].Path == p {
			return &inv.Entries[i]
		}
	}
	return nil
}

func hasWarning(inv *Inventory, code string) bool {
	for _, w := range inv.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// Reproduces the motivating layout: one entity hard-linked into keyword
// folders, one symlink, one separate copy in another root.
func TestWalkHardlinksAndSymlinks(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "A")
	b := filepath.Join(base, "B")
	orig := filepath.Join(a, "__files", "movie-original.mp4")
	write(t, orig, "video-bytes-1")
	write(t, filepath.Join(a, "__files", "clip.mov"), "video-bytes-2")
	link(t, orig, filepath.Join(a, "keyword1", "movie-a.mp4"))
	link(t, orig, filepath.Join(a, "keyword2", "renamed-video.mp4"))
	symlink(t, orig, filepath.Join(a, "keyword3", "movie-shortcut.mp4"))
	write(t, filepath.Join(b, "archive", "another-name.mp4"), "video-bytes-1")

	inv, err := Walk(context.Background(), Options{
		Roots:        []string{a, b},
		ProtectRoots: []string{filepath.Join(a, "__files")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.PhysicalFiles != 3 {
		t.Fatalf("physical files = %d, want 3 (orig, clip, another)", inv.Stats.PhysicalFiles)
	}
	pf := fileByPath(inv, orig)
	if pf == nil {
		t.Fatal("original not found")
	}
	if len(pf.KnownPaths) != 3 {
		t.Errorf("known paths = %v, want 3", pf.KnownPaths)
	}
	if len(pf.SymlinkRefs) != 1 {
		t.Errorf("symlink refs = %v, want 1", pf.SymlinkRefs)
	}
	if !pf.Protected || pf.ProtectedByRoot == "" {
		t.Errorf("original should be protected: %+v", pf)
	}
	if pf.UnverifiedExternalLinks {
		t.Errorf("all 3 links were found; should not flag external links (nlink=%d)", pf.Nlink)
	}
	if inv.Stats.HardlinkAliases != 2 {
		t.Errorf("aliases = %d, want 2", inv.Stats.HardlinkAliases)
	}
	// Logical counts links 3x, physical counts once.
	if inv.Stats.LogicalBytes != 13*3+13+13 || inv.Stats.PhysicalBytes != 13*3 {
		t.Errorf("logical=%d physical=%d", inv.Stats.LogicalBytes, inv.Stats.PhysicalBytes)
	}
	e := entryByPath(inv, filepath.Join(a, "keyword3", "movie-shortcut.mp4"))
	if e == nil || e.Kind != model.KindSymlink || e.SymlinkStatus != model.SymlinkOK || e.PhysicalFileID != pf.ID {
		t.Errorf("symlink entry: %+v", e)
	}
	other := fileByPath(inv, filepath.Join(b, "archive", "another-name.mp4"))
	if other == nil || other.Protected {
		t.Errorf("other copy should exist and be unprotected: %+v", other)
	}
}

func TestWalkExternalHardlinkIsFlagged(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	orig := filepath.Join(root, "v.mp4")
	write(t, orig, "x")
	link(t, orig, filepath.Join(outside, "v-external.mp4"))
	inv, err := Walk(context.Background(), Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	pf := fileByPath(inv, orig)
	if pf == nil {
		t.Fatal("missing")
	}
	if !pf.UnverifiedExternalLinks {
		t.Errorf("nlink=%d known=%d should flag unverified external links", pf.Nlink, len(pf.KnownPaths))
	}
	if pf.ExternalLinkCount() != 1 {
		t.Errorf("external link count = %d, want 1", pf.ExternalLinkCount())
	}
}

func TestWalkBrokenCycleAndOutsideSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, filepath.Join(root, "real.mp4"), "x")
	write(t, filepath.Join(base, "elsewhere", "out.mp4"), "y")
	symlink(t, filepath.Join(root, "missing.mp4"), filepath.Join(root, "broken.mp4"))
	symlink(t, filepath.Join(root, "loop-b.mp4"), filepath.Join(root, "loop-a.mp4"))
	symlink(t, filepath.Join(root, "loop-a.mp4"), filepath.Join(root, "loop-b.mp4"))
	symlink(t, filepath.Join(base, "elsewhere", "out.mp4"), filepath.Join(root, "outside.mp4"))
	symlink(t, filepath.Join(base, "elsewhere"), filepath.Join(root, "dirlink"))

	inv, err := Walk(context.Background(), Options{Roots: []string{root}, FollowSymlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.PhysicalFiles != 1 {
		t.Errorf("physical files = %d, want 1", inv.Stats.PhysicalFiles)
	}
	if e := entryByPath(inv, filepath.Join(root, "broken.mp4")); e == nil || e.SymlinkStatus != model.SymlinkBroken {
		t.Errorf("broken: %+v", e)
	}
	if e := entryByPath(inv, filepath.Join(root, "loop-a.mp4")); e == nil || (e.SymlinkStatus != model.SymlinkCycle && e.SymlinkStatus != model.SymlinkUnresolved) {
		t.Errorf("cycle: %+v", e)
	}
	if e := entryByPath(inv, filepath.Join(root, "outside.mp4")); e == nil || e.SymlinkStatus != model.SymlinkOutsideRoots || e.PhysicalFileID != "" {
		t.Errorf("outside: %+v", e)
	}
	if e := entryByPath(inv, filepath.Join(root, "dirlink")); e == nil || e.SymlinkStatus != model.SymlinkOutsideRoots {
		t.Errorf("dir outside roots should not be followed: %+v", e)
	}
	for _, code := range []string{"symlink_broken", "symlink_outside_roots"} {
		if !hasWarning(inv, code) {
			t.Errorf("missing warning %s", code)
		}
	}
}

func TestWalkFollowsDirectorySymlinkOnceWithoutCycling(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, filepath.Join(root, "sub", "v.mp4"), "x")
	symlink(t, filepath.Join(root, "sub"), filepath.Join(root, "sublink"))
	symlink(t, root, filepath.Join(root, "sub", "up"))

	inv, err := Walk(context.Background(), Options{Roots: []string{root}, FollowSymlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.PhysicalFiles != 1 {
		t.Errorf("physical files = %d, want 1", inv.Stats.PhysicalFiles)
	}
	pf := fileByPath(inv, filepath.Join(root, "sub", "v.mp4"))
	if pf == nil {
		t.Fatal("missing")
	}
	// The file is reachable via root/sub and root/sublink but it is one entity.
	if len(pf.KnownPaths) < 1 {
		t.Errorf("known paths %v", pf.KnownPaths)
	}
	if !hasWarning(inv, "directory_cycle") {
		t.Errorf("expected directory_cycle warning; warnings=%v", inv.Warnings)
	}
	// Without following, the symlinked dir is only recorded.
	inv2, _ := Walk(context.Background(), Options{Roots: []string{root}})
	if e := entryByPath(inv2, filepath.Join(root, "sublink")); e != nil {
		t.Errorf("without --follow-symlinks a dir symlink with non-video name should be skipped: %+v", e)
	}
}

func TestWalkNestedAndDuplicateRoots(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, filepath.Join(root, "sub", "v.mp4"), "x")
	inv, err := Walk(context.Background(), Options{Roots: []string{root, filepath.Join(root, "sub"), root}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.PhysicalFiles != 1 || inv.Stats.Files != 1 {
		t.Errorf("stats %+v", inv.Stats)
	}
	if !hasWarning(inv, "root_nested") || !hasWarning(inv, "root_duplicate") {
		t.Errorf("warnings %v", inv.Warnings)
	}
}

func TestWalkExcludesExtensionsAndHidden(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, filepath.Join(root, "keep.MP4"), "x")
	write(t, filepath.Join(root, "notes.txt"), "x")
	write(t, filepath.Join(root, ".hidden", "h.mp4"), "x")
	write(t, filepath.Join(root, "@eaDir", "thumb.mp4"), "x")
	write(t, filepath.Join(root, "skipme", "s.mp4"), "x")
	write(t, filepath.Join(root, "deep", "cache", "c.mp4"), "x")
	inv, err := Walk(context.Background(), Options{Roots: []string{root}, Excludes: []string{"skipme", "deep/cache"}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Files != 1 {
		var paths []string
		for _, e := range inv.Entries {
			paths = append(paths, e.Path)
		}
		t.Errorf("files = %d, want 1: %v", inv.Stats.Files, paths)
	}
	inv2, _ := Walk(context.Background(), Options{Roots: []string{root}, IncludeHidden: true, Extensions: []string{"txt"}})
	if inv2.Stats.Files != 1 || fileByPath(inv2, filepath.Join(root, "notes.txt")) == nil {
		t.Errorf("custom extension: files=%d", inv2.Stats.Files)
	}
}

func TestWalkUnicodeAndSpecialPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ルート 日本語")
	names := []string{"動画 ファイル.mp4", "with space.mp4", "quote'n\"dollar$.mp4", "semi;colon&amp.mp4", "-leading-dash.mp4"}
	if runtime.GOOS == "windows" {
		names = []string{"動画 ファイル.mp4", "with space.mp4", "quote'n dollar$.mp4", "semi;colon&amp.mp4", "-leading-dash.mp4"}
	}
	for _, n := range names {
		write(t, filepath.Join(root, n), n)
	}
	inv, err := Walk(context.Background(), Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Files != len(names) {
		t.Errorf("files = %d, want %d", inv.Stats.Files, len(names))
	}
}

func TestWalkUnreadableDirectoryIsWarningNotFatal(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission test not applicable")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, filepath.Join(root, "ok.mp4"), "x")
	locked := filepath.Join(root, "locked")
	write(t, filepath.Join(locked, "secret.mp4"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	inv, err := Walk(context.Background(), Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Files != 1 || !hasWarning(inv, "directory_unreadable") || inv.Stats.Failures == 0 {
		t.Errorf("stats=%+v warnings=%v", inv.Stats, inv.Warnings)
	}
}

func TestWalkCancellation(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(root, "d", string(rune('a'+i)), "v.mp4"), "x")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Walk(ctx, Options{Roots: []string{root}})
	if err == nil {
		t.Error("expected context error")
	}
}

// A hard link inside a protected root protects the entity even when another
// path of it sorts first ("Movies" < "__files").
func TestWalkProtectionCoversEveryHardLinkedPath(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "A")
	first := filepath.Join(a, "Movies", "x.mp4")
	write(t, first, "video")
	link(t, first, filepath.Join(a, "__files", "x.mp4"))
	inv, err := Walk(context.Background(), Options{Roots: []string{a}, ProtectRoots: []string{filepath.Join(a, "__files")}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, first)
	if f == nil || len(f.KnownPaths) != 2 || !f.Protected {
		t.Fatalf("entity must be protected through its __files link: %+v", f)
	}
	if hasWarning(inv, "protect_root_unmatched") {
		t.Fatal("protect root matched a file but was reported as unmatched")
	}
}

// A symlink without a video extension still references its target.
func TestWalkSymlinkWithoutVideoExtension(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "A", "movie.mp4")
	write(t, target, "video")
	symlink(t, target, filepath.Join(base, "A", "latest"))
	inv, err := Walk(context.Background(), Options{Roots: []string{filepath.Join(base, "A")}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, target)
	if f == nil || len(f.SymlinkRefs) != 1 {
		t.Fatalf("symlink reference not recorded: %+v", f)
	}
}

func TestWalkMissingRootIsAFailure(t *testing.T) {
	base := t.TempDir()
	write(t, filepath.Join(base, "file.mp4"), "x")
	inv, err := Walk(context.Background(), Options{Roots: []string{filepath.Join(base, "nope"), filepath.Join(base, "file.mp4")}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Failures != 2 || !hasWarning(inv, "root_unreadable") || !hasWarning(inv, "root_not_directory") {
		t.Fatalf("missing and non-directory roots must count as failures: %+v %+v", inv.Stats, inv.Warnings)
	}
}

func TestWalkProtectRootChecks(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "A")
	write(t, filepath.Join(a, "m.mp4"), "x")
	if err := os.MkdirAll(filepath.Join(a, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Walk(context.Background(), Options{Roots: []string{a}, ProtectRoots: []string{filepath.Join(a, "typo")}}); err == nil {
		t.Fatal("a missing protect root must be an error")
	}
	inv, err := Walk(context.Background(), Options{Roots: []string{a}, ProtectRoots: []string{filepath.Join(a, "empty"), filepath.Join(base, "elsewhere")}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(inv, "protect_root_unmatched") || !hasWarning(inv, "protect_root_outside_roots") {
		t.Fatalf("ineffective protect roots must be reported: %+v", inv.Warnings)
	}
}

func TestWalkFlagsNonUTF8Paths(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		t.Skip("filesystem requires valid Unicode names")
	}
	base := t.TempDir()
	p := filepath.Join(base, "bad\xff.mp4")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Skipf("cannot create non-UTF-8 name: %v", err)
	}
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	if f := fileByPath(inv, p); f == nil || !f.PathsNotUTF8 || !hasWarning(inv, "path_not_utf8") {
		t.Fatalf("non-UTF-8 path not flagged: %+v", f)
	}
}

// "café" in NFC (U+00E9) and NFD (e + U+0301) are two names on ext4 but look
// identical, and SMB or macOS may resolve them to one file.
func TestWalkFlagsNFCNFDConflicts(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("APFS/HFS+ treat the two forms as one name")
	}
	base := t.TempDir()
	nfc := filepath.Join(base, "café.mp4")
	nfd := filepath.Join(base, "café.mp4")
	write(t, nfc, "same")
	write(t, nfd, "same")
	if _, err := os.Stat(nfd); err != nil || fileCount(t, base) != 2 {
		t.Skip("filesystem normalizes names")
	}
	write(t, filepath.Join(base, "plain.mp4"), "same")
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{nfc, nfd} {
		if f := fileByPath(inv, p); f == nil || !f.UnicodeConflict {
			t.Fatalf("%q not flagged: %+v", p, f)
		}
	}
	if f := fileByPath(inv, filepath.Join(base, "plain.mp4")); f == nil || f.UnicodeConflict {
		t.Fatalf("unrelated file flagged: %+v", f)
	}
	if !hasWarning(inv, "unicode_normalization_conflict") {
		t.Fatal("warning missing")
	}
}

func fileCount(t *testing.T, dir string) int {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// A copy in a recycle bin or snapshot must never become the keeper:
// emptying the bin would then lose both copies. Such folders are never
// scanned, not even with --include-hidden, and a root inside one is skipped.
func TestWalkNeverScansTrashFolders(t *testing.T) {
	base := t.TempDir()
	write(t, filepath.Join(base, "B", "v.mp4"), "video")
	for _, d := range []string{"@Recycle", "#recycle", "#snapshot", "lost+found", ".Trash-1000", "$RECYCLE.BIN"} {
		write(t, filepath.Join(base, "L", d, "v.mp4"), "video")
	}
	for _, hidden := range []bool{false, true} {
		inv, err := Walk(context.Background(), Options{Roots: []string{base}, IncludeHidden: hidden})
		if err != nil {
			t.Fatal(err)
		}
		if len(inv.Files) != 1 || inv.Files[0].PrimaryPath() != filepath.Join(base, "B", "v.mp4") {
			t.Fatalf("include-hidden=%v: trash copies scanned: %+v", hidden, inv.Files)
		}
	}
	inv, err := Walk(context.Background(), Options{Roots: []string{filepath.Join(base, "L", "@Recycle")}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(inv, "root_in_trash") || inv.Stats.Failures != 1 || len(inv.Files) != 0 {
		t.Fatalf("root inside a recycle bin: %+v %+v", inv.Stats, inv.Warnings)
	}
}

// Links below the depth limit or in an unreadable excluded folder cannot be
// checked, so the scan is partial rather than complete.
func TestWalkUncheckedLinksMakeScanPartial(t *testing.T) {
	base := t.TempDir()
	deep := base
	for i := 0; i <= maxDepth+1; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Skipf("cannot build a deep tree: %v", err)
	}
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(inv, "depth_exceeded") || inv.Stats.Failures == 0 {
		t.Fatalf("depth limit must count as a failure: %+v", inv.Stats)
	}

	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("permissions not enforced")
	}
	base2 := t.TempDir()
	hidden := filepath.Join(base2, ".links")
	write(t, filepath.Join(hidden, "x"), "x")
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(hidden, 0o755)
	inv, err = Walk(context.Background(), Options{Roots: []string{base2}})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(inv, "excluded_directory_unreadable") || inv.Stats.Failures == 0 {
		t.Fatalf("unreadable excluded folder must count as a failure: %+v %+v", inv.Stats, inv.Warnings)
	}
}

// Recycle bins are recognised by rule, not only by a fixed list, and the
// rule also applies where a followed directory link leads.
func TestTrashRulesCoverNamesAndFollowedLinks(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "movies", "a.mp4")
	write(t, live, "video")
	for _, d := range []string{
		".local/share/Trash/files", "Recycled", "Network Trash Folder", ".recycle",
		"@GMT-2024.01.01-00.00.00", "@sharebin", "data/files_trashbin",
		"timeshift-btrfs/snapshots/x", ".zfs/snapshot/daily", "@sharesnap/video/GMT+09-2024.01.01-00.00",
		".Recycle.Bin", "Backups.backupdb/mac", ".stversions", "FileHistory/u",
	} {
		write(t, filepath.Join(base, d, "a.mp4"), "video")
	}
	write(t, filepath.Join(base, "#recycle", "old", "a.mp4"), "video")
	write(t, filepath.Join(base, "snaps", "a.mp4"), "video")
	symlink(t, "#recycle", filepath.Join(base, "bin"))
	write(t, filepath.Join(base, "xbin"), xsym("#recycle/old"))
	symlink(t, "snaps", filepath.Join(base, "s"))

	inv, err := Walk(context.Background(), Options{Roots: []string{base}, IncludeHidden: true, FollowSymlinks: true, Excludes: []string{"snaps"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range inv.Files {
		if f.PrimaryPath() != live {
			t.Errorf("scanned outside the live library: %v", f.KnownPaths)
		}
	}
	if !hasWarning(inv, "trash_folder_skipped") {
		t.Error("skipped trash folders not reported")
	}
}

// Ordinary folders whose names merely contain "trash", "snapshot" or
// "recycle" are scanned normally, and links inside a real bin still count.
func TestTrashNamesAreExactAndBinsKeepLinks(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{"Snapshots", "Trash Humpers (2009)", "Recycled Art"} {
		write(t, filepath.Join(base, d, "v.mp4"), d)
	}
	target := filepath.Join(base, "lib", "a.mp4")
	write(t, target, "video")
	symlink(t, "../lib/a.mp4", filepath.Join(base, "#recycle", "fav.mp4"))
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 4 {
		t.Fatalf("ordinary folders were skipped: %d files", len(inv.Files))
	}
	if f := fileByPath(inv, target); f == nil || len(f.SymlinkRefs) != 1 {
		t.Fatalf("link inside a recycle bin not counted: %+v", f)
	}
}

// A hard link that survives only in a bin inside the protected library must
// not make the outside copy a protected keeper.
func TestProtectionIgnoresLinksInBins(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "dl", "a.mp4")
	write(t, a, "hello")
	link(t, a, filepath.Join(base, "lib", "#recycle", "a.mp4"))
	write(t, filepath.Join(base, "lib", "keep", "z.mp4"), "x")
	inv, err := Walk(context.Background(), Options{Roots: []string{base}, ProtectRoots: []string{filepath.Join(base, "lib")}})
	if err != nil {
		t.Fatal(err)
	}
	// It is shielded (never proposed), but must not be a trusted keeper.
	if f := fileByPath(inv, a); f == nil || f.InProtectedLibrary {
		t.Fatalf("trusted keeper only through a link in a bin: %+v", f)
	}
}

// @eaDir is not scanned for videos but links inside it still count.
func TestLinksInsideEaDirCount(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "Old", "a.mp4")
	write(t, target, "v")
	symlink(t, "../a.mp4", filepath.Join(base, "Old", "@eaDir", "l.mp4"))
	write(t, filepath.Join(base, "Old", "@eaDir", "thumb.mp4"), "thumbnail")
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	if f := fileByPath(inv, target); f == nil || len(f.SymlinkRefs) != 1 {
		t.Fatalf("link inside @eaDir not counted: %+v", f)
	}
	if fileByPath(inv, filepath.Join(base, "Old", "@eaDir", "thumb.mp4")) != nil {
		t.Fatal("a video in @eaDir was scanned")
	}
}

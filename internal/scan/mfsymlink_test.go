package scan

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
)

// xsym builds a Minshall–French symlink file the way the Linux CIFS client
// writes one.
func xsym(target string) string {
	s := fmt.Sprintf("XSym\n%04d\n%x\n%s\n", len(target), md5.Sum([]byte(target)), target)
	return s + strings.Repeat(" ", mfSymlinkSize-len(s))
}

func TestParseMFSymlink(t *testing.T) {
	good := xsym("../videos/movie.mp4")
	if len(good) != 1067 {
		t.Fatalf("fixture size %d", len(good))
	}
	if got, ok := parseMFSymlink([]byte(good)); !ok || got != "../videos/movie.mp4" {
		t.Fatalf("valid link: %q %v", got, ok)
	}
	// The kernel compares only 17 hex digits of the MD5 and does not check
	// the newline after the target; such files are links too.
	lenient := map[string]string{
		"md5 tail differs": good[:27] + strings.Repeat("0", 15) + good[42:],
		"no newline":       good[:43+19] + "X" + good[43+20:],
		"space padded len": "XSym\n  19" + good[9:],
	}
	for name, s := range lenient {
		if got, ok := parseMFSymlink([]byte(s)); !ok || got != "../videos/movie.mp4" {
			t.Errorf("%s: rejected a link the kernel follows", name)
		}
	}
	bad := map[string]string{
		"wrong checksum": strings.Replace(good, "movie.mp4", "movie.mkv", 1),
		"short":          good[:1066],
		"long":           good + " ",
		"no magic":       "xsym" + good[4:],
		"length beyond":  "XSym\n1025" + good[9:],
		"md5 head":       good[:10] + "g" + good[11:],
		"signed length":  "XSym\n+019" + good[9:],
	}
	for name, s := range bad {
		if _, ok := parseMFSymlink([]byte(s)); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWalkMinshallFrenchSymlinks(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "videos", "movie.mp4")
	write(t, target, "video bytes")
	link := filepath.Join(base, "shortcuts", "movie.mp4")
	write(t, link, xsym("../videos/movie.mp4"))
	// Two links to the same target are byte-identical; they must never be
	// treated as duplicate videos. One has no extension.
	write(t, filepath.Join(base, "shortcuts", "latest"), xsym("../videos/movie.mp4"))
	write(t, filepath.Join(base, "shortcuts", "gone.mp4"), xsym("../videos/missing.mp4"))
	write(t, filepath.Join(base, "loop", "a.mp4"), xsym("b.mp4"))
	write(t, filepath.Join(base, "loop", "b.mp4"), xsym("a.mp4"))
	// A file that only looks like a link (bad checksum) stays a regular file.
	fake := strings.Replace(xsym("x.mp4"), "x.mp4", "y.mp4", 1)
	write(t, filepath.Join(base, "fake.mp4"), fake)

	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, target)
	if f == nil || len(f.SymlinkRefs) != 2 {
		t.Fatalf("target must list both XSym links: %+v", f)
	}
	e := entryByPath(inv, link)
	if e == nil || e.Kind != model.KindSymlink || e.SymlinkFormat != model.SymlinkFormatMinshallFrench || e.SymlinkStatus != model.SymlinkOK {
		t.Fatalf("XSym entry: %+v", e)
	}
	if fileByPath(inv, link) != nil {
		t.Fatal("an XSym link must not be a physical video file")
	}
	if e := entryByPath(inv, filepath.Join(base, "shortcuts", "gone.mp4")); e == nil || e.SymlinkStatus != model.SymlinkBroken {
		t.Fatalf("broken XSym: %+v", e)
	}
	if e := entryByPath(inv, filepath.Join(base, "loop", "a.mp4")); e == nil || e.SymlinkStatus != model.SymlinkCycle {
		t.Fatalf("XSym cycle: %+v", e)
	}
	if fileByPath(inv, filepath.Join(base, "fake.mp4")) == nil {
		t.Fatal("a file with a bad checksum must stay a regular file")
	}
}

// Links through an XSym directory link, a real symlink to an XSym file,
// and hidden or excluded XSym files all keep their reference.
func TestWalkResolvesLinksThroughXSym(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "B", "copy.mp4")
	write(t, target, "video bytes")
	write(t, filepath.Join(base, "C", "dl"), xsym("../B"))            // XSym directory link
	symlink(t, "dl/copy.mp4", filepath.Join(base, "C", "viadir.mp4")) // real link through it
	write(t, filepath.Join(base, "C", "x.mp4"), xsym("dl/copy.mp4"))  // XSym through it
	write(t, filepath.Join(base, "D", "xs.mp4"), xsym("../B/copy.mp4"))
	symlink(t, "xs.mp4", filepath.Join(base, "D", "toxsym.mp4")) // real link to an XSym file
	write(t, filepath.Join(base, "E", ".hidden.mp4"), xsym("../B/copy.mp4"))
	write(t, filepath.Join(base, "E", "skip-me.mp4"), xsym("../B/copy.mp4"))

	inv, err := Walk(context.Background(), Options{Roots: []string{base}, Excludes: []string{"skip-*"}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, target)
	if f == nil {
		t.Fatal("target not found")
	}
	want := []string{"C/viadir.mp4", "C/x.mp4", "D/toxsym.mp4", "D/xs.mp4", "E/.hidden.mp4", "E/skip-me.mp4"}
	got := map[string]bool{}
	for _, r := range f.SymlinkRefs {
		rel, _ := filepath.Rel(base, r)
		got[filepath.ToSlash(rel)] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("reference %s missing; refs = %v", w, f.SymlinkRefs)
		}
	}
	if inv.Stats.Failures != 0 {
		t.Errorf("failures %d: %+v", inv.Stats.Failures, inv.Warnings)
	}
}

func TestWalkFollowsXSymDirectoryLink(t *testing.T) {
	base := t.TempDir()
	write(t, filepath.Join(base, "other", "v.mp4"), "video")
	write(t, filepath.Join(base, "lib", "dirlink"), xsym("../other"))
	inv, err := Walk(context.Background(), Options{Roots: []string{base}, FollowSymlinks: true})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.Failures != 0 {
		t.Fatalf("following an XSym directory link must not fail: %+v", inv.Warnings)
	}
	if e := entryByPath(inv, filepath.Join(base, "lib", "dirlink")); e == nil || e.SymlinkStatus != model.SymlinkDirectory {
		t.Fatalf("XSym directory link: %+v", e)
	}
}

// A link made in a container or on another machine (absolute target that
// does not exist here) still names a file; that file is held for review.
func TestWalkUnresolvedLinkNamesFile(t *testing.T) {
	base := t.TempDir()
	b := filepath.Join(base, "other", "B.mp4")
	write(t, b, "video")
	write(t, filepath.Join(base, "other", "unrelated.mp4"), "video")
	symlink(t, "/data/media/other/b.mp4", filepath.Join(base, "lib", "fav.mp4"))
	write(t, filepath.Join(base, "lib", "mac"), xsym("/Volumes/NAS/other/b.mp4"))
	inv, err := Walk(context.Background(), Options{Roots: []string{base}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, b)
	if f == nil || len(f.PossibleLinkRefs) != 2 {
		t.Fatalf("unresolved links naming B.mp4 not attached: %+v", f)
	}
	if u := fileByPath(inv, filepath.Join(base, "other", "unrelated.mp4")); u == nil || len(u.PossibleLinkRefs) != 0 {
		t.Fatalf("unrelated file flagged: %+v", u)
	}
}

// "dl/../clip.mp4" means the parent of wherever dl points: the kernel
// resolves dl first. Cleaning the text first would pick the wrong file.
func TestWalkDotDotAfterLinkIsPhysical(t *testing.T) {
	for _, kind := range []string{"symlink", "xsym"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "sub", "clip.mp4")
			decoy := filepath.Join(base, "clip.mp4")
			write(t, real, "x")
			write(t, decoy, "x")
			if err := os.MkdirAll(filepath.Join(base, "sub", "deep"), 0o755); err != nil {
				t.Fatal(err)
			}
			symlink(t, "sub/deep", filepath.Join(base, "dl"))
			link := filepath.Join(base, "L.mp4")
			if kind == "symlink" {
				symlink(t, "dl/../clip.mp4", link)
			} else {
				write(t, link, xsym("dl/../clip.mp4"))
			}
			inv, err := Walk(context.Background(), Options{Roots: []string{base}})
			if err != nil {
				t.Fatal(err)
			}
			if f := fileByPath(inv, real); f == nil || len(f.SymlinkRefs) != 1 {
				t.Fatalf("the file the link reaches lost its reference: %+v", f)
			}
			if f := fileByPath(inv, decoy); f == nil || len(f.SymlinkRefs) != 0 {
				t.Fatalf("reference attached to the wrong file: %+v", f)
			}
		})
	}
}

// Links in hidden, excluded and NAS metadata folders still count as
// references; videos in them are still not scanned.
func TestWalkLinksInHiddenAndExcludedFolders(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "z", "target_long.mp4")
	write(t, target, "video")
	symlink(t, "../z/target_long.mp4", filepath.Join(base, ".h", "ref.mp4"))
	write(t, filepath.Join(base, "x", "ref2"), xsym("../z/target_long.mp4"))
	write(t, filepath.Join(base, "x", "inner.mp4"), "video in an excluded folder")
	symlink(t, "../z/target_long.mp4", filepath.Join(base, "@eaDir", "thumb.mp4"))
	// An XSym whose name has a non-video extension is still a link.
	write(t, filepath.Join(base, "Show.S01E01"), xsym("z/target_long.mp4"))

	inv, err := Walk(context.Background(), Options{Roots: []string{base}, Excludes: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	f := fileByPath(inv, target)
	if f == nil || len(f.SymlinkRefs) != 4 {
		t.Fatalf("want refs from .h/ref.mp4, x/ref2, @eaDir/thumb.mp4 and Show.S01E01: %+v", f)
	}
	if fileByPath(inv, filepath.Join(base, "x", "inner.mp4")) != nil {
		t.Fatal("a video in an excluded folder was scanned")
	}
	if inv.Stats.Failures != 0 {
		t.Fatalf("failures: %+v", inv.Warnings)
	}
}

package filesystem

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIdentityHardlinksShareIdentity(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	c := filepath.Join(dir, "c.bin")
	if err := os.WriteFile(a, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links not supported here: %v", err)
	}
	if err := os.WriteFile(c, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	ia := IdentityOf(a, mustLstat(t, a))
	ib := IdentityOf(b, mustLstat(t, b))
	ic := IdentityOf(c, mustLstat(t, c))
	if !ia.Known || !ib.Known || !ic.Known {
		t.Fatalf("identity not known on %s: %+v %+v %+v", runtime.GOOS, ia, ib, ic)
	}
	if ia.ID != ib.ID {
		t.Errorf("hard links should share identity: %+v vs %+v", ia.ID, ib.ID)
	}
	if ia.ID == ic.ID {
		t.Errorf("distinct files should differ: %+v vs %+v", ia.ID, ic.ID)
	}
	if ia.NlinkKnown && ia.Nlink != 2 {
		t.Errorf("nlink = %d, want 2", ia.Nlink)
	}
	if ic.NlinkKnown && ic.Nlink != 1 {
		t.Errorf("nlink = %d, want 1", ic.Nlink)
	}
}

func TestIdentitySymlinkIsDistinctFromTarget(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	l := filepath.Join(dir, "l.bin")
	if err := os.WriteFile(a, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, l); err != nil {
		t.Skipf("symlinks not supported here: %v", err)
	}
	ia := IdentityOf(a, mustLstat(t, a))
	il := IdentityOf(l, mustLstat(t, l))
	if !ia.Known || !il.Known {
		t.Skip("identity unavailable")
	}
	if ia.ID == il.ID {
		t.Errorf("symlink (Lstat) must not share identity with target")
	}
	st, err := os.Stat(l)
	if err != nil {
		t.Fatal(err)
	}
	it := IdentityOf(l, st)
	if it.Known && it.ID != ia.ID {
		// On Windows the handle-based identity of a followed symlink equals the target.
		t.Errorf("Stat through symlink should resolve to target identity: %+v vs %+v", it.ID, ia.ID)
	}
}

func TestInspectRootDoesNotFail(t *testing.T) {
	ri := InspectRoot(t.TempDir())
	if ri.Confidence == "" {
		t.Errorf("confidence must be set: %+v", ri)
	}
}

func mustLstat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

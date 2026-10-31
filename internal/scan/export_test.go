package scan

import (
	"os"
	"path/filepath"

	"github.com/hidetzu/reelwarden/internal/filesystem"
)

// SetPlatform replaces the identity and filesystem probes for a test and
// returns a function that restores them.
func SetPlatform(id func(string, os.FileInfo) filesystem.Identity, fs func(string) filesystem.RootInfo) (restore func()) {
	oldID, oldFS := identityOf, inspectRoot
	identityOf, inspectRoot = id, fs
	return func() { identityOf, inspectRoot = oldID, oldFS }
}

// SetMounts replaces the mount table (mount point -> source path) for a test.
func SetMounts(m map[string]string) (restore func()) {
	old := mountTable
	mm := map[string][]string{}
	for k, v := range m {
		mm[k] = []string{v}
	}
	mountTable = func() map[string][]string { return mm }
	return func() { mountTable = old }
}

// SetMountTable replaces the full mount table (mount point -> its root in the
// source filesystem, then other places the content lives) for a test.
func SetMountTable(m map[string][]string) (restore func()) {
	old := mountTable
	mountTable = func() map[string][]string { return m }
	return func() { mountTable = old }
}

// RealTempDir returns t.TempDir() with links resolved. Tests that fake
// identities or mount tables by path must use the spelling the walker sees
// (/private/var on macOS, long names instead of 8.3 short names on Windows).
func RealTempDir(t interface {
	TempDir() string
	Fatal(...any)
}) string {
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

//go:build linux

package filesystem

import (
	"strings"
	"testing"
)

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/vol/#recycle\040(1)`); got != "/vol/#recycle (1)" {
		t.Fatalf("got %q", got)
	}
}

func TestMountSourceOfRoot(t *testing.T) {
	if MountSource("/") == "" {
		t.Skip("no /proc/self/mountinfo")
	}
}

func TestZFSSnapshotMountIsMarked(t *testing.T) {
	line := "120 30 0:55 / /mnt/old rw - zfs tank/video@daily rw"
	if got := sourceRoot(strings.Fields(line)); !strings.HasPrefix(got, "/.zfs/snapshot") {
		t.Fatalf("got %q", got)
	}
	if got := sourceRoot(strings.Fields("1 2 0:5 /x /m rw - ext4 /dev/sda1 rw")); got != "/x" {
		t.Fatalf("got %q", got)
	}
}

// A filesystem mounted on a bin's path and bind-mounted elsewhere has root
// "/" at both mount points; the other mount point gives it away.
func TestEquivalentPathsRevealBinMountedFilesystem(t *testing.T) {
	type e struct{ dev, root, mnt string }
	all := []e{{"0:9", "/", "/x/@Recycle"}, {"0:9", "/", "/lib/inn3"}, {"8:1", "/", "/"}}
	got := equivalentPaths(all, func(x e) (string, string, string) { return x.dev, x.root, x.mnt })
	found := false
	for _, p := range got["/lib/inn3"] {
		found = found || p == "/x/@Recycle"
	}
	if !found {
		t.Fatalf("got %v", got["/lib/inn3"])
	}
}

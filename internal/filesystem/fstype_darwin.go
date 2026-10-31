//go:build darwin

package filesystem

import (
	"syscall"

	"github.com/hidetzu/reelwarden/internal/model"
)

func inspectRoot(path string) RootInfo {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return RootInfo{Confidence: model.ConfidenceUnknown}
	}
	name := cString(st.Fstypename[:])
	switch name {
	case "nfs", "smbfs", "afpfs", "webdav", "cifs", "fuse", "osxfuse", "macfuse", "lifs":
		return RootInfo{Filesystem: name, Network: true, Confidence: model.ConfidenceLow}
	case "apfs", "hfs", "ufs":
		return RootInfo{Filesystem: name, Confidence: model.ConfidenceHigh}
	}
	// FAT/exFAT (msdos, exfat) derive file numbers from directory entries,
	// and unlisted filesystems (bindfs, third-party drivers) may not give
	// stable identities; never trust them for a candidate.
	return RootInfo{Filesystem: name, Confidence: model.ConfidenceUnknown}
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

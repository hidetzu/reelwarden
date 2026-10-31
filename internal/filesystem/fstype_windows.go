//go:build windows

package filesystem

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/hidetzu/reelwarden/internal/model"
)

func inspectRoot(path string) RootInfo {
	abs, err := filepath.Abs(path)
	if err != nil {
		return RootInfo{Confidence: model.ConfidenceUnknown}
	}
	vol := filepath.VolumeName(abs)
	if strings.HasPrefix(vol, `\\`) {
		return RootInfo{Filesystem: "unc", Network: true, Confidence: model.ConfidenceLow}
	}
	root := vol + `\`
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return RootInfo{Confidence: model.ConfidenceUnknown}
	}
	switch windows.GetDriveType(p) {
	case windows.DRIVE_REMOTE:
		return RootInfo{Filesystem: "remote", Network: true, Confidence: model.ConfidenceLow}
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK, windows.DRIVE_CDROM:
		fsName := make([]uint16, windows.MAX_PATH+1)
		if err := windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))); err != nil {
			return RootInfo{Filesystem: "unknown", Confidence: model.ConfidenceUnknown}
		}
		name := strings.ToLower(windows.UTF16ToString(fsName))
		switch name {
		case "ntfs":
			return RootInfo{Filesystem: name, Confidence: model.ConfidenceHigh}
		}
		// FAT/exFAT file indexes come from directory entries, ReFS file IDs
		// are 128-bit (the 64-bit index used here may not be unique), and
		// user-mode drivers (WinFsp, rclone, Dokan) report arbitrary names:
		// none is trusted for identity.
		return RootInfo{Filesystem: name, Confidence: model.ConfidenceUnknown}
	}
	return RootInfo{Filesystem: "unknown", Confidence: model.ConfidenceUnknown}
}

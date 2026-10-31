//go:build windows

package filesystem

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/hidetzu/reelwarden/internal/model"
)

// identityOf opens the file without following reparse points when info
// describes a symlink, and reads the volume serial number and file index.
// This mirrors what os.SameFile does internally.
func identityOf(path string, info os.FileInfo) Identity {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Identity{}
	}
	attrs := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if info != nil && info.Mode()&os.ModeSymlink != 0 {
		attrs |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, attrs, 0)
	if err != nil {
		return Identity{}
	}
	defer windows.CloseHandle(h)
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bhfi); err != nil {
		return Identity{}
	}
	return Identity{
		ID: model.FileIdentity{
			Device: uint64(bhfi.VolumeSerialNumber),
			Inode:  uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow),
		},
		Nlink:      uint64(bhfi.NumberOfLinks),
		Known:      true,
		NlinkKnown: true,
	}
}

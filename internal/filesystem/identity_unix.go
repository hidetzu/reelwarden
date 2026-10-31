//go:build !windows

package filesystem

import (
	"os"
	"syscall"

	"github.com/hidetzu/reelwarden/internal/model"
)

func identityOf(_ string, info os.FileInfo) Identity {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return Identity{}
	}
	// Dev, Ino and Nlink have different widths on different Unix platforms.
	dev := uint64(st.Dev)     //nolint:unconvert // uint64 on linux/amd64, narrower elsewhere
	ino := uint64(st.Ino)     //nolint:unconvert // see above
	nlink := uint64(st.Nlink) //nolint:unconvert // see above
	return Identity{
		ID:         model.FileIdentity{Device: dev, Inode: ino},
		Nlink:      nlink,
		Known:      true,
		NlinkKnown: true,
		ChangeTime: changeTime(st),
	}
}

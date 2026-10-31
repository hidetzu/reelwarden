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
	return Identity{
		ID:         model.FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)},
		Nlink:      uint64(st.Nlink),
		Known:      true,
		NlinkKnown: true,
		ChangeTime: changeTime(st),
	}
}

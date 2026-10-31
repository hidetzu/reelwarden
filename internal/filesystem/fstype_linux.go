//go:build linux

package filesystem

import (
	"syscall"

	"github.com/hidetzu/reelwarden/internal/model"
)

// Magic numbers from linux/magic.h.
var fsNames = map[int64]struct {
	name    string
	network bool
	// untrusted: identities are not stable or unique. Stacked filesystems
	// show another filesystem's files under new identities; FAT and exFAT
	// get inode numbers from iunique(), which change once evicted.
	untrusted bool
}{
	0x6969:     {"nfs", true, false},
	0xFF534D42: {"cifs", true, false},
	0xFE534D42: {"smb2", true, false},
	0x517B:     {"smb", true, false},
	0x65735546: {"fuse", true, false}, // FUSE: unknown backend, treat as low confidence
	0x61636673: {"afs", true, false},
	0x19830326: {"fhgfs", true, false},
	0x47504653: {"gpfs", true, false},
	0x01021994: {"tmpfs", false, false},
	0xEF53:     {"ext4", false, false},
	0x9123683E: {"btrfs", false, false},
	0x58465342: {"xfs", false, false},
	0x2FC12FC1: {"zfs", false, false},
	0x3434:     {"nilfs", false, false},
	0xF2F52010: {"f2fs", false, false},
	0x4d44:     {"vfat", false, true},
	0x5346544e: {"ntfs", false, false},
	0x65735543: {"fusectl", false, false},
	0x794c7630: {name: "overlayfs", untrusted: true},
	0x61756673: {name: "aufs", untrusted: true},
	0xf15f:     {name: "ecryptfs", untrusted: true},
	0xca451a4e: {"bcachefs", false, false},
	0x482b:     {"hfsplus", false, false},
	0x15013346: {"udf", false, false},
	0xE0F5E1E2: {"erofs", false, false},
	0x858458f6: {"ramfs", false, false},
	0x73717368: {"squashfs", false, false},
	0x9660:     {"iso9660", false, false},
	0x6165676C: {"pstore", false, false},
	0x01021997: {"v9fs", true, false},
	0xC97E8168: {"logfs", false, false},
	0x52654973: {"reiserfs", false, false},
	0x3153464a: {"jfs", false, false},
	0x7461636f: {"ocfs2", true, false},
	0x53464846: {"wslfs", true, false},
	0x2011BAB0: {"exfat", false, true},
}

// fsMagic normalises statfs f_type: on 32-bit Linux (ARMv7) it is int32, so
// magic numbers above 0x7fffffff (btrfs, cifs, f2fs, ...) arrive negative.
// Magic numbers are 32-bit, so the low 32 bits identify the filesystem.
func fsMagic(raw int64) int64 { return int64(uint32(raw)) }

func inspectRoot(path string) RootInfo {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return RootInfo{Confidence: model.ConfidenceUnknown}
	}
	if fs, ok := fsNames[fsMagic(int64(st.Type))]; ok {
		conf := model.ConfidenceHigh
		if fs.network || fs.untrusted {
			conf = model.ConfidenceLow
		}
		return RootInfo{Filesystem: fs.name, Network: fs.network, Confidence: conf}
	}
	// Unlisted filesystems (cluster, union or new local ones) may not give
	// stable identities; never trust them for a candidate.
	return RootInfo{Filesystem: "unknown", Confidence: model.ConfidenceUnknown}
}

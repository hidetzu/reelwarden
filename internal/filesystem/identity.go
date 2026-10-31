// Package filesystem isolates OS-specific file identity, link counting and
// filesystem-type detection behind a small portable API (docs/design.md §4).
package filesystem

import (
	"os"

	"github.com/hidetzu/reelwarden/internal/model"
)

// Identity describes the OS-level identity of a file.
type Identity struct {
	ID    model.FileIdentity
	Nlink uint64
	// Known is false when the platform could not provide an identity.
	Known bool
	// NlinkKnown is false when the platform could not provide a link count.
	NlinkKnown bool
	// ChangeTime is the inode change time (ctime) in Unix nanoseconds, or 0
	// when unknown. Unlike mtime it cannot be set back by the user, so it
	// invalidates cache entries for files rewritten with a restored mtime.
	ChangeTime int64
}

// IdentityOf returns the identity of the file described by info (from Lstat
// or Stat). path is used on platforms that need to open the file.
func IdentityOf(path string, info os.FileInfo) Identity {
	return identityOf(path, info)
}

// RootInfo describes the filesystem a root lives on.
type RootInfo struct {
	Filesystem string
	Network    bool
	Confidence string
}

// InspectRoot reports the filesystem type of a root directory and whether
// file identities on it should be trusted. Failures degrade to
// Confidence=unknown rather than errors.
func InspectRoot(path string) RootInfo {
	return inspectRoot(path)
}

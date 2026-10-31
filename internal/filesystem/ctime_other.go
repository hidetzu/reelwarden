//go:build !linux && !darwin && !windows

package filesystem

import "syscall"

// changeTime is not wired up on this platform; 0 means unknown.
func changeTime(*syscall.Stat_t) int64 { return 0 }

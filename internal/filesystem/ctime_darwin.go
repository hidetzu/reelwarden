//go:build darwin

package filesystem

import "syscall"

func changeTime(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }

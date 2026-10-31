//go:build !windows

package scan

import "syscall"

var syscallELOOP error = syscall.ELOOP

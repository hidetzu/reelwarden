//go:build windows

package scan

import "errors"

var syscallELOOP = errors.New("symlink loop")

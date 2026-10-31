//go:build !linux

package filesystem

// MountSource is only implemented on Linux; elsewhere it is unknown.
func MountSource(string) string { return "" }

func mountPoints() map[string][]string { return map[string][]string{} }

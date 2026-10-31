package filesystem

// MountPoints returns, for every mount point, the other places its content
// is known to live: its root inside the source filesystem (see MountSource)
// and the same place under other mounts of that filesystem. Empty where
// unknown.
func MountPoints() map[string][]string { return mountPoints() }

package model

import "strconv"

func formatIdentity(dev, ino uint64) string {
	return strconv.FormatUint(dev, 16) + ":" + strconv.FormatUint(ino, 16)
}

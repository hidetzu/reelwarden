//go:build !linux && !darwin && !windows

package filesystem

import "github.com/hidetzu/reelwarden/internal/model"

func inspectRoot(string) RootInfo {
	return RootInfo{Filesystem: "unknown", Confidence: model.ConfidenceUnknown}
}

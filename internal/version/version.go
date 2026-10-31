// Package version holds build metadata injected with -ldflags.
package version

import (
	"runtime"
	"runtime/debug"

	"github.com/hidetzu/reelwarden/internal/model"
)

// Set at build time: -X github.com/hidetzu/reelwarden/internal/version.Version=...
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info returns the tool info embedded in documents.
func Info() model.ToolInfo {
	ver, commit := Version, Commit
	if bi, ok := debug.ReadBuildInfo(); ok {
		// `go install ...@v0.1.0-dev.1` sets the module version, not ldflags.
		if ver == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			ver = bi.Main.Version
		}
		if commit == "" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && len(s.Value) >= 12 {
					commit = s.Value[:12]
				}
			}
		}
	}
	return model.ToolInfo{Name: model.ToolName, Version: ver, Commit: commit, GoOS: runtime.GOOS, GoArch: runtime.GOARCH}
}

// String is the one-line version shown by `version` and `--version`.
func String() string {
	i := Info()
	s := i.Name + " " + i.Version
	if i.Commit != "" {
		s += " " + i.Commit
	}
	if Date != "" {
		s += " " + Date
	}
	return s + " " + i.GoOS + "/" + i.GoArch
}

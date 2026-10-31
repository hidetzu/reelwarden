// Package cli implements the reelwarden command line. All commands are
// read-only with respect to scanned files (docs/design.md §10).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
	"github.com/hidetzu/reelwarden/internal/version"
)

// Exit codes (docs/design.md §11).
const (
	ExitOK         = 0
	ExitRuntime    = 1
	ExitUsage      = 2
	ExitDependency = 3
	ExitPartial    = 4
	ExitCancelled  = 130
)

// ExitError carries an exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

func usageErr(f string, a ...any) error {
	return &ExitError{Code: ExitUsage, Err: fmt.Errorf(f, a...)}
}

// IO bundles the standard streams so tests can capture them.
type IO struct {
	In     io.Reader
	Out    io.Writer
	Err    io.Writer
	ErrTTY bool
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, streams IO) int {
	root := NewRoot(streams)
	root.SetArgs(args)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(streams.Err, "reelwarden:", ee.Err)
		}
		return ee.Code
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(streams.Err, "reelwarden: cancelled")
		return ExitCancelled
	}
	fmt.Fprintln(streams.Err, "reelwarden:", err)
	// cobra flag and argument errors are usage errors.
	msg := err.Error()
	if strings.Contains(msg, "unknown flag") || strings.Contains(msg, "unknown command") || strings.Contains(msg, "accepts") ||
		strings.Contains(msg, "requires at least") || strings.Contains(msg, "invalid argument") || strings.Contains(msg, "flag needs an argument") {
		return ExitUsage
	}
	return ExitRuntime
}

// NewRoot builds the command tree.
func NewRoot(streams IO) *cobra.Command {
	root := &cobra.Command{
		Use:   "reelwarden",
		Short: "Find duplicate and similar videos, explain what to keep, plan safely (read-only)",
		Long: `reelwarden inventories video libraries without modifying them.

It separates paths, physical files (hard links) and content, finds
byte-identical copies (no FFmpeg needed) and visually similar re-encodes
(FFmpeg/FFprobe required), explains which copy is worth keeping, and writes
a read-only plan. It never deletes, moves or relinks files.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newScanCmd(streams), newReportCmd(streams), newPlanCmd(streams), newDoctorCmd(streams), newVersionCmd(streams))
	return root
}

// outputGuard describes the files an output path must never replace.
type outputGuard struct {
	exts []string          // extra extensions treated as video (scan --ext, or a scan's recorded list)
	res  *model.ScanResult // every path of this scan is off limits
	// input is the scan file being read (report, plan).
	input string
}

// hasVideoExt reports whether path has a default video extension or one of
// extra. Trailing dots and spaces are ignored because Windows strips them.
func hasVideoExt(path string, extra []string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimRight(path, ". ")))
	if ext == "" {
		return false
	}
	for _, list := range [][]string{scan.DefaultExtensions, extra} {
		for _, e := range list {
			e = strings.ToLower(strings.TrimSpace(e))
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			if e == ext {
				return true
			}
		}
	}
	return false
}

// checkOutputPath refuses output paths that could replace a scanned file.
func checkOutputPath(path string, g outputGuard) error {
	if path == "" || path == "-" || path == os.DevNull {
		return nil
	}
	if hasVideoExt(path, g.exts) {
		return usageErr("refusing to write output to %q: it has a video file extension", path)
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return usageErr("refusing to write output to %q: not a regular file", path)
	}
	if g.res == nil {
		return nil
	}
	target := canonicalPath(path)
	if g.input != "" && g.input != "-" {
		same := canonicalPath(g.input) == target
		if in, err := os.Stat(g.input); err == nil {
			if out, err := os.Stat(path); err == nil && os.SameFile(in, out) {
				same = true // through a symlink or a hard link
			}
		}
		if same {
			return usageErr("refusing to write output to %q: it is the input scan file", path)
		}
	}
	for _, e := range g.res.Entries {
		if canonicalPath(e.Path) == target {
			return usageErr("refusing to write output to %q: it is a scanned path", path)
		}
	}
	return nil
}

// canonicalPath resolves the parent directory's symlinks so equivalent
// spellings of one location compare equal; the final element is kept.
func canonicalPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	dir, base := filepath.Split(abs)
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	return filepath.Join(dir, base)
}

// writeOutput writes data to path atomically (temp file + rename), or to
// stdout when path is empty or "-". It refuses paths that checkOutputPath
// rejects, so a scanned file is never replaced.
func writeOutput(path string, g outputGuard, stdout io.Writer, write func(io.Writer) error) error {
	if path == "" || path == "-" {
		return write(stdout)
	}
	if err := checkOutputPath(path, g); err != nil {
		return err
	}
	if path == os.DevNull {
		return write(io.Discard)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".reelwarden-*.tmp")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := write(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	ok = true
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// loadScan reads and validates a scan document.
func loadScan(path string) (*model.ScanResult, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, &ExitError{Code: ExitRuntime, Err: fmt.Errorf("open scan result: %w", err)}
		}
		defer f.Close()
		r = f
	}
	var res model.ScanResult
	dec := json.NewDecoder(r)
	if err := dec.Decode(&res); err != nil {
		return nil, &ExitError{Code: ExitRuntime, Err: fmt.Errorf("%s is not a valid scan result: %w", path, err)}
	}
	if res.SchemaVersion != model.SchemaVersion {
		return nil, &ExitError{Code: ExitRuntime, Err: fmt.Errorf("%s has schema version %q; this build reads %q", path, res.SchemaVersion, model.SchemaVersion)}
	}
	if res.Tool.Name != model.ToolName {
		return nil, &ExitError{Code: ExitRuntime, Err: fmt.Errorf("%s was not produced by reelwarden scan", path)}
	}
	if err := validateScan(&res); err != nil {
		return nil, &ExitError{Code: ExitRuntime, Err: fmt.Errorf("%s is not a consistent scan result: %w", path, err)}
	}
	return &res, nil
}

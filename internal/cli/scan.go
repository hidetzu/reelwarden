package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/hidetzu/reelwarden/internal/cache"
	"github.com/hidetzu/reelwarden/internal/engine"
	"github.com/hidetzu/reelwarden/internal/fingerprint"
	"github.com/hidetzu/reelwarden/internal/media"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
	"github.com/hidetzu/reelwarden/internal/version"
)

type scanFlags struct {
	mode           string
	output         string
	protect        []string
	exclude        []string
	ext            string
	followSymlinks bool
	includeHidden  bool
	ioWorkers      int
	mediaWorkers   int
	cacheDir       string
	noCache        bool
	ffmpeg         string
	ffprobe        string
	samples        int
	timeout        time.Duration
	quiet          bool
}

func newScanCmd(streams IO) *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan <root>...",
		Short: "Inventory roots and find byte-identical (exact) or visually similar (video) files",
		Long: `Inventory roots and find byte-identical (exact) or visually similar (video) files.

A copy is proposed as redundant only when an identical copy stays under a
--protect-root you trust. Without --protect-root, duplicates are listed for
review only. Nothing is ever deleted, moved or relinked.`,
		Example: `  reelwarden scan ./Library ./Old --protect-root ./Library --output scan.json
  reelwarden scan ./Library ./Old --protect-root ./Library --mode video --output scan.json`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), streams, f, args)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.mode, "mode", model.ModeExact, "exact (no FFmpeg) or video (needs ffmpeg and ffprobe)")
	fl.StringVarP(&f.output, "output", "o", "", "write the scan JSON here (default: stdout)")
	fl.StringArrayVar(&f.protect, "protect-root", nil, "library you trust: its files are never proposed, and only copies of them can be (required for any candidate; repeatable)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "glob matched against names and root-relative paths (repeatable)")
	fl.StringVar(&f.ext, "ext", "", "comma-separated extensions to include (default: common video extensions)")
	fl.BoolVar(&f.followSymlinks, "follow-symlinks", false, "descend into symlinked directories inside the roots (cycle-safe)")
	fl.BoolVar(&f.includeHidden, "include-hidden", false, "include dot-directories and NAS metadata folders (@eaDir); recycle bins and snapshots are never scanned")
	fl.IntVar(&f.ioWorkers, "io-workers", 4, "parallel file readers for hashing (keep low on slow NAS)")
	fl.IntVar(&f.mediaWorkers, "media-workers", 0, "parallel ffprobe/ffmpeg processes (default: min(4, CPUs/2))")
	fl.StringVar(&f.cacheDir, "cache-dir", "", "cache directory (default: user cache dir/reelwarden)")
	fl.BoolVar(&f.noCache, "no-cache", false, "do not read or write the cache")
	fl.StringVar(&f.ffmpeg, "ffmpeg-path", "", "ffmpeg binary (default: from PATH)")
	fl.StringVar(&f.ffprobe, "ffprobe-path", "", "ffprobe binary (default: from PATH)")
	fl.IntVar(&f.samples, "samples", 16, "frames sampled per video for visual fingerprints (8-64)")
	fl.DurationVar(&f.timeout, "timeout", media.DefaultTimeout, "timeout per ffprobe/ffmpeg invocation")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "no progress output")
	return cmd
}

func runScan(ctx context.Context, streams IO, f *scanFlags, roots []string) error {
	if f.mode != model.ModeExact && f.mode != model.ModeVideo {
		return usageErr("--mode must be exact or video, got %q", f.mode)
	}
	if f.samples < 8 || f.samples > 64 {
		return usageErr("--samples must be between 8 and 64")
	}
	if f.ioWorkers < 1 || f.ioWorkers > 64 || f.mediaWorkers < 0 || f.mediaWorkers > 64 {
		return usageErr("worker counts must be between 1 and 64")
	}
	opts := engine.Options{
		Scan: scan.Options{
			Roots: roots, ProtectRoots: f.protect, Excludes: f.exclude,
			FollowSymlinks: f.followSymlinks, IncludeHidden: f.includeHidden,
		},
		Mode:         f.mode,
		IOWorkers:    f.ioWorkers,
		MediaWorkers: f.mediaWorkers,
		Tool:         version.Info(),
	}
	if f.ext != "" {
		for _, e := range strings.Split(f.ext, ",") {
			if e = strings.TrimSpace(e); e != "" {
				opts.Scan.Extensions = append(opts.Scan.Extensions, e)
			}
		}
	}
	guard := outputGuard{exts: opts.Scan.Extensions}
	if err := checkOutputPath(f.output, guard); err != nil {
		return err
	}
	for _, p := range f.protect {
		if st, err := os.Stat(p); err != nil {
			return usageErr("--protect-root %q: %v", p, err)
		} else if !st.IsDir() {
			return usageErr("--protect-root %q: not a directory", p)
		}
		if abs, err := filepath.Abs(p); err == nil {
			if r, err := filepath.EvalSymlinks(abs); err == nil && scan.InTrash(r) {
				return usageErr("--protect-root %q is inside a recycle bin, snapshot or backup folder", p)
			}
		}
	}
	if f.mode == model.ModeVideo {
		tools, err := media.Locate(ctx, f.ffmpeg, f.ffprobe)
		if err != nil && ctx.Err() != nil {
			return &ExitError{Code: ExitCancelled, Err: errors.New("cancelled while checking FFmpeg")}
		}
		if err != nil {
			hint := "install FFmpeg (https://ffmpeg.org/download.html) or pass --ffmpeg-path/--ffprobe-path; --mode exact works without it"
			return &ExitError{Code: ExitDependency, Err: fmt.Errorf("--mode video needs ffmpeg and ffprobe: %w\n  %s", err, hint)}
		}
		tools.Timeout = f.timeout
		opts.Tools = tools
		vp := fingerprint.DefaultVisualParams()
		vp.Samples = f.samples
		opts.Visual = vp
	}
	if !f.noCache {
		dir := f.cacheDir
		if dir == "" {
			d, err := cache.DefaultDir()
			if err != nil {
				fmt.Fprintln(streams.Err, "warning: no user cache directory; continuing without cache:", err)
			}
			dir = d
		}
		if dir != "" {
			if r, ok := rootContaining(dir, roots); ok {
				// The cache database would itself be scanned and rewritten.
				if hasVideoExt("cache.db", opts.Scan.Extensions) {
					return usageErr("cache directory %s is inside scan root %s and cache.db matches --ext; use --cache-dir elsewhere or --no-cache", dir, r)
				}
				fmt.Fprintf(streams.Err, "warning: cache directory %s is inside scan root %s; consider --cache-dir elsewhere\n", dir, r)
			}
			store, err := cache.Open(dir)
			if err != nil {
				return &ExitError{Code: ExitRuntime, Err: err}
			}
			defer store.Close()
			opts.Cache = store
		}
	}
	prog := newProgress(streams.Err, streams.ErrTTY && !f.quiet)
	opts.Progress = prog.update
	res, runErr := engine.Run(ctx, opts)
	prog.done()
	if res == nil {
		if errors.Is(runErr, context.Canceled) {
			return &ExitError{Code: ExitCancelled, Err: errors.New("cancelled before any result was produced")}
		}
		return &ExitError{Code: ExitRuntime, Err: runErr}
	}
	guard.res = res
	if err := writeOutput(f.output, guard, streams.Out, func(w io.Writer) error { return writeJSON(w, res) }); err != nil {
		return err
	}
	// Problems with the roots themselves are shown even with --quiet: a
	// mistyped path must not look like "no duplicates".
	for _, w := range res.Warnings {
		if strings.HasPrefix(w.Code, "root_") || strings.HasPrefix(w.Code, "protect_root_") {
			fmt.Fprintf(streams.Err, "warning: %s: %s: %s\n", w.Code, w.Path, w.Message)
		}
	}
	if !f.quiet && len(f.protect) == 0 && res.Stats.Groups > 0 {
		fmt.Fprintln(streams.Err, "note: no --protect-root was given; duplicates are listed but no copy is proposed as redundant. Protect the library you trust to get candidates.")
	}
	if !f.quiet {
		s := res.Stats
		fmt.Fprintf(streams.Err, "scan %s: %d paths, %d physical files (%d hard-link aliases), %d groups, %d uncertain pairs, %d failures, %d cache hits, %.1fs\n",
			res.Status, s.EntriesFound, s.PhysicalFiles, s.HardlinkAliases, s.Groups, s.UncertainEdges, s.Failures, s.CacheHits, s.ElapsedSeconds)
		fmt.Fprintln(streams.Err, "No files were modified. The scan output contains absolute paths; treat it as private.")
	}
	switch res.Status {
	case model.StatusCancelled:
		return &ExitError{Code: ExitCancelled, Err: errors.New("scan cancelled; partial result written")}
	case model.StatusPartial:
		return &ExitError{Code: ExitPartial, Err: fmt.Errorf("scan completed with %d failure(s); see warnings in the output", res.Stats.Failures)}
	}
	return nil
}

type progress struct {
	w       io.Writer
	enabled bool
	mu      sync.Mutex
	last    time.Time
	shown   bool
}

func newProgress(w io.Writer, enabled bool) *progress { return &progress{w: w, enabled: enabled} }

func (p *progress) update(stage string, done, total int) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.last) < 150*time.Millisecond && done != total {
		return
	}
	p.last = time.Now()
	p.shown = true
	if total > 0 {
		fmt.Fprintf(p.w, "\r\033[K%s: %d/%d", stage, done, total)
	} else {
		fmt.Fprintf(p.w, "\r\033[K%s: %d", stage, done)
	}
}

func (p *progress) done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.shown {
		fmt.Fprint(p.w, "\r\033[K")
	}
}

// rootContaining reports the scan root that contains dir, if any.
func rootContaining(dir string, roots []string) (string, bool) {
	d := canonicalPath(dir)
	// The cache directory itself may be a symlink into a root. Resolve the
	// absolute form: EvalSymlinks keeps a relative path relative.
	if abs, err := filepath.Abs(dir); err == nil {
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			d = r
		}
	}
	for _, r := range roots {
		cr := canonicalPath(r)
		if res, err := filepath.EvalSymlinks(cr); err == nil {
			cr = res
		}
		if rel, err := filepath.Rel(cr, d); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return r, true
		}
	}
	return "", false
}

// Package engine orchestrates the scan pipeline: inventory, exact hashing,
// media probing, visual fingerprinting and matching. It reads files but
// never writes, renames or deletes them.
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hidetzu/reelwarden/internal/cache"
	"github.com/hidetzu/reelwarden/internal/fingerprint"
	"github.com/hidetzu/reelwarden/internal/match"
	"github.com/hidetzu/reelwarden/internal/media"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
)

// MediaTools is what the engine needs from ffprobe/ffmpeg.
type MediaTools interface {
	media.Prober
	media.FrameExtractor
	ProbeVersion() string
}

// Options configure a scan.
type Options struct {
	Scan         scan.Options
	Mode         string
	IOWorkers    int
	MediaWorkers int
	PartialChunk int64
	Cache        cache.Store
	Tools        MediaTools // required for ModeVideo
	Visual       model.VisualParams
	Match        model.MatchParams
	Tool         model.ToolInfo
	// Progress receives stage updates; may be nil.
	Progress func(stage string, done, total int)
}

// Defaults fills unset options.
func (o *Options) Defaults() {
	if o.IOWorkers <= 0 {
		o.IOWorkers = 4
	}
	if o.MediaWorkers <= 0 {
		o.MediaWorkers = max(1, min(4, runtime.NumCPU()/2))
	}
	if o.PartialChunk <= 0 {
		o.PartialChunk = fingerprint.DefaultPartialChunk
	}
	if o.Cache == nil {
		o.Cache = cache.Disabled()
	}
	if o.Visual.Samples == 0 {
		o.Visual = fingerprint.DefaultVisualParams()
	}
	if o.Match.FrameHammingThreshold == 0 {
		o.Match = match.DefaultParams()
	}
	if o.Mode == "" {
		o.Mode = model.ModeExact
	}
}

type state struct {
	opts     Options
	mu       sync.Mutex
	files    []model.PhysicalFile
	warnings []model.Warning
	stats    *model.ScanStats
}

func (s *state) warn(code, path, msg string) {
	s.mu.Lock()
	s.warnings = append(s.warnings, model.Warning{Code: code, Path: path, Message: msg})
	s.mu.Unlock()
}

func (s *state) fileErr(i int, code, msg string) {
	s.mu.Lock()
	f := &s.files[i]
	f.Errors = append(f.Errors, msg)
	s.stats.Failures++
	s.warnings = append(s.warnings, model.Warning{Code: code, Path: f.PrimaryPath(), Message: msg})
	s.mu.Unlock()
}

func (s *state) progress(stage string, done, total int) {
	if s.opts.Progress != nil {
		s.opts.Progress(stage, done, total)
	}
}

// Run executes the scan. It returns a result even when cancelled (status
// "cancelled") together with the context error.
func Run(ctx context.Context, opts Options) (*model.ScanResult, error) {
	opts.Defaults()
	if opts.Mode != model.ModeExact && opts.Mode != model.ModeVideo {
		return nil, fmt.Errorf("unknown mode %q", opts.Mode)
	}
	if opts.Mode == model.ModeVideo && opts.Tools == nil {
		return nil, errors.New("video mode requires ffmpeg and ffprobe")
	}
	start := time.Now()
	userProgress := opts.Scan.Progress
	if userProgress == nil && opts.Progress != nil {
		opts.Scan.Progress = func(n int) { opts.Progress("inventory", n, 0) }
	}
	inv, walkErr := scan.Walk(ctx, opts.Scan)
	if inv == nil {
		return nil, walkErr
	}
	st := &state{opts: opts, files: inv.Files, warnings: inv.Warnings, stats: &inv.Stats}

	res := &model.ScanResult{
		SchemaVersion:  model.SchemaVersion,
		Tool:           opts.Tool,
		GeneratedAt:    time.Now().UTC(),
		Roots:          inv.Roots,
		ProtectedRoots: inv.ProtectedRoots,
		Params: model.ScanParams{
			Mode:            opts.Mode,
			Extensions:      extensionsOf(opts.Scan.Extensions),
			Excludes:        opts.Scan.Excludes,
			FollowSymlinks:  opts.Scan.FollowSymlinks,
			IOWorkers:       opts.IOWorkers,
			MediaWorkers:    opts.MediaWorkers,
			PartialHashSize: opts.PartialChunk,
			CacheEnabled:    opts.Cache.Enabled(),
		},
		Entries: inv.Entries,
		Notice:  model.ReadOnlyNotice,
	}

	if walkErr == nil {
		st.exact(ctx)
	}
	if ctx.Err() == nil && opts.Mode == model.ModeVideo {
		vp := opts.Visual
		mp := opts.Match
		res.Params.Visual = &vp
		res.Params.Match = &mp
		res.Params.FFmpegVersion = opts.Tools.Version()
		res.Params.FFprobeVersion = opts.Tools.ProbeVersion()
		st.probe(ctx)
		if ctx.Err() == nil {
			st.visual(ctx)
		}
	}

	m := match.Build(st.files, opts.Match, opts.Mode == model.ModeVideo)
	res.Files = st.files
	res.Edges = m.Edges
	res.Groups = m.Groups
	res.Warnings = st.warnings
	// Keep arrays non-null so the JSON schema is stable.
	if res.Warnings == nil {
		res.Warnings = []model.Warning{}
	}
	if res.Entries == nil {
		res.Entries = []model.PathEntry{}
	}
	if res.Files == nil {
		res.Files = []model.PhysicalFile{}
	}
	if res.Edges == nil {
		res.Edges = []model.MatchEdge{}
	}
	if res.Groups == nil {
		res.Groups = []model.DuplicateGroup{}
	}
	stats := *st.stats
	for _, e := range m.Edges {
		switch e.Relation {
		case model.RelationByteIdentical:
			stats.ByteIdenticalEdges++
		case model.RelationVisuallySimilar:
			stats.VisualEdges++
		case model.RelationUncertain:
			stats.UncertainEdges++
		}
	}
	stats.Groups = len(m.Groups)
	stats.ElapsedSeconds = time.Since(start).Round(time.Millisecond).Seconds()
	res.Stats = stats

	switch {
	case ctx.Err() != nil:
		res.Status = model.StatusCancelled
	case stats.Failures > 0:
		res.Status = model.StatusPartial
	default:
		res.Status = model.StatusComplete
	}
	return res, ctx.Err()
}

func extensionsOf(exts []string) []string {
	if len(exts) == 0 {
		return scan.DefaultExtensions
	}
	return exts
}

// cacheKey identifies a physical file in the cache.
func cacheKey(f *model.PhysicalFile) string {
	// An unconfirmed identity may be shared by different files.
	if f.Identity != nil && f.IdentityStatus == model.IdentityKnown {
		return "id:" + f.Identity.Key()
	}
	return "path:" + f.PrimaryPath()
}

func validator(f *model.PhysicalFile, algo int, params, tool string) cache.Validator {
	return cache.Validator{Size: f.Size, MTime: f.MTime, CTimeUnixNano: f.CTimeUnixNano, AlgorithmVersion: algo, Params: params, ToolVersion: tool}
}

// recheck re-stats the primary path and marks the file as changed if size
// or mtime moved since the inventory.
func (s *state) recheck(i int) bool {
	s.mu.Lock()
	f := &s.files[i]
	p := f.PrimaryPath()
	size, mtime := f.Size, f.MTime
	s.mu.Unlock()
	info, err := os.Stat(p)
	if err != nil {
		s.fileErr(i, "file_disappeared", "file could not be re-checked after reading: "+err.Error())
		s.mu.Lock()
		s.files[i].ChangedDuringScan = true
		s.mu.Unlock()
		return false
	}
	if info.Size() != size || !info.ModTime().UTC().Equal(mtime) {
		s.mu.Lock()
		s.files[i].ChangedDuringScan = true
		s.files[i].Errors = append(s.files[i].Errors, "changed_during_scan: size or mtime changed while reading; results for this file discarded")
		s.stats.Failures++
		s.warnings = append(s.warnings, model.Warning{Code: "changed_during_scan", Path: p, Message: "file changed while it was being read"})
		s.mu.Unlock()
		return false
	}
	return true
}

// parallel runs fn(i) for each index with at most workers concurrently.
func parallel(ctx context.Context, idx []int, workers int, fn func(i int)) {
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, i := range idx {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			if ctx.Err() != nil {
				return
			}
			fn(i)
		}(i)
	}
	wg.Wait()
}

type counter struct {
	mu   sync.Mutex
	n    int
	tot  int
	name string
	s    *state
}

func (c *counter) inc() {
	c.mu.Lock()
	c.n++
	n := c.n
	c.mu.Unlock()
	c.s.progress(c.name, n, c.tot)
}

// exact performs size bucketing, partial hashing and full hashing.
func (s *state) exact(ctx context.Context) {
	bySize := map[int64][]int{}
	for i := range s.files {
		f := &s.files[i]
		if f.Size == 0 || f.ChangedDuringScan {
			continue
		}
		bySize[f.Size] = append(bySize[f.Size], i)
	}
	var cands []int
	for _, idx := range bySize {
		if len(idx) > 1 {
			cands = append(cands, idx...)
		}
	}
	sort.Ints(cands)
	params := "chunk=" + strconv.FormatInt(s.opts.PartialChunk, 10)
	exacts := make([]model.ExactFingerprint, len(s.files))

	// Partial hashes.
	c := &counter{name: "partial-hash", tot: len(cands), s: s}
	parallel(ctx, cands, s.opts.IOWorkers, func(i int) {
		defer c.inc()
		f := &s.files[i]
		var cached model.ExactFingerprint
		if ok, _ := s.opts.Cache.Get(cache.BucketExact, cacheKey(f), validator(f, fingerprint.ExactAlgorithmVersion, params, ""), &cached); ok && cached.PartialSHA256 != "" {
			// Only the partial hash is reused, as a pre-filter. A byte_identical
			// claim always rests on a full hash computed in this run, so a stale
			// entry can at worst hide a duplicate, never invent one.
			exacts[i] = model.ExactFingerprint{PartialSHA256: cached.PartialSHA256, FromCache: true}
			s.mu.Lock()
			s.stats.CacheHits++
			s.mu.Unlock()
			return
		}
		d, full, err := fingerprint.PartialHash(ctx, f.PrimaryPath(), f.Size, s.opts.PartialChunk)
		if err != nil {
			if ctx.Err() == nil {
				s.fileErr(i, "hash_failed", "partial hash failed: "+err.Error())
			}
			return
		}
		if !s.recheck(i) {
			return
		}
		exacts[i].PartialSHA256 = d
		if full {
			exacts[i].SHA256 = d
		}
		s.mu.Lock()
		s.stats.PartialHashes++
		s.mu.Unlock()
	})
	if ctx.Err() != nil {
		return
	}

	// Full hashes for partial-hash buckets.
	byPartial := map[string][]int{}
	for _, i := range cands {
		if exacts[i].PartialSHA256 == "" {
			continue
		}
		k := strconv.FormatInt(s.files[i].Size, 10) + ":" + exacts[i].PartialSHA256
		byPartial[k] = append(byPartial[k], i)
	}
	var fulls []int
	for _, idx := range byPartial {
		if len(idx) > 1 {
			for _, i := range idx {
				if exacts[i].SHA256 == "" {
					fulls = append(fulls, i)
				}
			}
		}
	}
	sort.Ints(fulls)
	c = &counter{name: "full-hash", tot: len(fulls), s: s}
	parallel(ctx, fulls, s.opts.IOWorkers, func(i int) {
		defer c.inc()
		f := &s.files[i]
		d, err := fingerprint.FullHash(ctx, f.PrimaryPath())
		if err != nil {
			if ctx.Err() == nil {
				s.fileErr(i, "hash_failed", "full hash failed: "+err.Error())
			}
			return
		}
		if !s.recheck(i) {
			return
		}
		exacts[i].SHA256 = d
		exacts[i].FromCache = false
		s.mu.Lock()
		s.stats.FullHashes++
		s.mu.Unlock()
	})

	for _, i := range cands {
		e := exacts[i]
		if e.PartialSHA256 == "" || s.files[i].ChangedDuringScan {
			continue
		}
		f := &s.files[i]
		ec := e
		f.Exact = &ec
		if !e.FromCache {
			store := model.ExactFingerprint{PartialSHA256: e.PartialSHA256}
			_ = s.opts.Cache.Put(cache.BucketExact, cacheKey(f), validator(f, fingerprint.ExactAlgorithmVersion, params, ""), f.PrimaryPath(), store)
		}
	}
}

// probe runs ffprobe on every file.
func (s *state) probe(ctx context.Context) {
	idx := make([]int, 0, len(s.files))
	for i := range s.files {
		if !s.files[i].ChangedDuringScan {
			idx = append(idx, i)
		}
	}
	ver := s.opts.Tools.ProbeVersion()
	c := &counter{name: "probe", tot: len(idx), s: s}
	parallel(ctx, idx, s.opts.MediaWorkers, func(i int) {
		defer c.inc()
		f := &s.files[i]
		v := validator(f, media.ProbeAlgorithmVersion, "", ver)
		var mi model.MediaInfo
		if ok, _ := s.opts.Cache.Get(cache.BucketMedia, cacheKey(f), v, &mi); ok {
			mi.FromCache = true
			s.mu.Lock()
			f.Media = &mi
			s.stats.CacheHits++
			s.stats.Probed++
			s.mu.Unlock()
			return
		}
		got, err := s.opts.Tools.Probe(ctx, f.PrimaryPath())
		if err != nil {
			if ctx.Err() == nil {
				s.fileErr(i, "probe_failed", "ffprobe failed: "+err.Error())
			}
			return
		}
		if got.ProbeError != "" {
			s.fileErr(i, "probe_error", "ffprobe reported: "+got.ProbeError)
		}
		if !s.recheck(i) {
			return
		}
		s.mu.Lock()
		f.Media = got
		s.stats.Probed++
		s.mu.Unlock()
		if got.ProbeError == "" {
			_ = s.opts.Cache.Put(cache.BucketMedia, cacheKey(f), v, f.PrimaryPath(), got)
		}
	})
}

// visual computes visual fingerprints for files with a primary video stream.
func (s *state) visual(ctx context.Context) {
	var idx []int
	for i := range s.files {
		f := &s.files[i]
		if f.ChangedDuringScan || f.Media == nil {
			continue
		}
		if f.Media.PrimaryVideo() == nil {
			s.warn("no_video_stream", f.PrimaryPath(), "no video stream; only exact matching applies")
			continue
		}
		if !f.Media.DurationKnown {
			s.warn("duration_unknown", f.PrimaryPath(), "duration unknown; visual fingerprint skipped")
			continue
		}
		idx = append(idx, i)
	}
	p := s.opts.Visual
	pk := fingerprint.ParamsKey(p)
	ver := s.opts.Tools.Version()
	c := &counter{name: "fingerprint", tot: len(idx), s: s}
	parallel(ctx, idx, s.opts.MediaWorkers, func(i int) {
		defer c.inc()
		f := &s.files[i]
		v := validator(f, fingerprint.VisualAlgorithmVersion, pk, ver)
		var fp model.VisualFingerprint
		if ok, _ := s.opts.Cache.Get(cache.BucketVisual, cacheKey(f), v, &fp); ok {
			fp.FromCache = true
			s.mu.Lock()
			f.Visual = &fp
			s.stats.CacheHits++
			s.stats.Fingerprinted++
			s.mu.Unlock()
			return
		}
		got, err := fingerprint.ComputeVisual(ctx, s.opts.Tools, f.PrimaryPath(), f.Media, p)
		if err != nil {
			if ctx.Err() == nil {
				s.fileErr(i, "fingerprint_failed", "visual fingerprint failed: "+err.Error())
			}
			return
		}
		if got.FailedCount > 0 {
			s.warn("frames_failed", f.PrimaryPath(), fmt.Sprintf("%d of %d sample frames could not be decoded", got.FailedCount, len(got.Frames)))
		}
		if !s.recheck(i) {
			return
		}
		s.mu.Lock()
		f.Visual = got
		s.stats.Fingerprinted++
		s.mu.Unlock()
		_ = s.opts.Cache.Put(cache.BucketVisual, cacheKey(f), v, f.PrimaryPath(), got)
	})
}

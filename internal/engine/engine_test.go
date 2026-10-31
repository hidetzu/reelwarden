package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hidetzu/reelwarden/internal/cache"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
)

// fakeTools simulates ffprobe/ffmpeg. onProbe can mutate the file to
// simulate concurrent writers.
type fakeTools struct {
	onProbe func(path string)
	probes  atomic.Int32
	frames  map[string]byte // per-path brightness seed
}

func (f *fakeTools) Version() string      { return "fake-ffmpeg" }
func (f *fakeTools) ProbeVersion() string { return "fake-ffprobe" }
func (f *fakeTools) ExtractAudio(context.Context, string, float64, int) ([]byte, error) {
	return nil, nil
}
func (f *fakeTools) Probe(_ context.Context, path string) (*model.MediaInfo, error) {
	f.probes.Add(1)
	if f.onProbe != nil {
		f.onProbe(path)
	}
	return &model.MediaInfo{DurationSec: 10, DurationKnown: true, VideoStreams: 1,
		Streams: []model.StreamInfo{{Index: 0, Type: "video", Codec: "h264", Width: 64, Height: 36}}}, nil
}
func (f *fakeTools) ExtractRGB(_ context.Context, path string, at float64, _, w, h int) ([]byte, error) {
	px := make([]byte, 0, w*h*3)
	seed := f.frames[filepath.Base(path)]
	for i := 0; i < w*h; i++ {
		v := byte((i*int(seed+3) + int(at*10)) % 251)
		px = append(px, v, v, v)
	}
	return px, nil
}

func write(t *testing.T, p, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVideoPipelineWithFakeTools(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.mp4"), "aaaa")
	write(t, filepath.Join(dir, "b.mkv"), "bbbbbb")
	write(t, filepath.Join(dir, "c.mp4"), "cccccccc")
	ft := &fakeTools{frames: map[string]byte{"a.mp4": 1, "b.mkv": 1, "c.mp4": 90}}
	res, err := Run(context.Background(), Options{Scan: scan.Options{Roots: []string{dir}}, Mode: model.ModeVideo, Tools: ft})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != model.StatusComplete || res.Stats.Probed != 3 || res.Stats.Fingerprinted != 3 {
		t.Fatalf("status %s stats %+v", res.Status, res.Stats)
	}
	if len(res.Groups) != 1 || len(res.Groups[0].Members) != 2 || res.Groups[0].Relation != model.RelationVisuallySimilar {
		t.Errorf("groups %+v edges %+v", res.Groups, res.Edges)
	}
	if res.Params.Visual == nil || res.Params.FFmpegVersion != "fake-ffmpeg" {
		t.Errorf("params %+v", res.Params)
	}
}

// 12: a file modified while it is being analysed is marked and excluded.
func TestChangedDuringScan(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.mp4")
	b := filepath.Join(dir, "b.mp4")
	write(t, a, "same")
	write(t, b, "same")
	ft := &fakeTools{frames: map[string]byte{"a.mp4": 1, "b.mp4": 1}, onProbe: func(p string) {
		if filepath.Base(p) == "b.mp4" {
			f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString("grown")
			f.Close()
		}
	}}
	res, err := Run(context.Background(), Options{Scan: scan.Options{Roots: []string{dir}}, Mode: model.ModeVideo, Tools: ft})
	if err != nil {
		t.Fatal(err)
	}
	var changed *model.PhysicalFile
	for i := range res.Files {
		if res.Files[i].PrimaryPath() == b {
			changed = &res.Files[i]
		}
	}
	if changed == nil || !changed.ChangedDuringScan || changed.Media != nil || changed.Visual != nil {
		t.Fatalf("b: %+v", changed)
	}
	if res.Status != model.StatusPartial {
		t.Errorf("status %s", res.Status)
	}
	for _, e := range res.Edges {
		if e.Relation == model.RelationVisuallySimilar {
			t.Errorf("no visual edge may involve a changed file: %+v", e)
		}
	}
	// The byte-identical edge was computed before the change; it remains
	// valid evidence about the bytes that were read, but decisions are
	// guarded by changed_during_scan.
}

func TestCancelledScanReturnsPartialResult(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.mp4", "b.mp4", "c.mp4"} {
		write(t, filepath.Join(dir, n), "x")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ft := &fakeTools{frames: map[string]byte{}, onProbe: func(string) { cancel() }}
	res, err := Run(ctx, Options{Scan: scan.Options{Roots: []string{dir}}, Mode: model.ModeVideo, Tools: ft, MediaWorkers: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if res == nil || res.Status != model.StatusCancelled {
		t.Fatalf("res %+v", res)
	}
}

func TestVideoModeRequiresTools(t *testing.T) {
	if _, err := Run(context.Background(), Options{Scan: scan.Options{Roots: []string{t.TempDir()}}, Mode: model.ModeVideo}); err == nil {
		t.Error("expected error")
	}
}

func TestEmptyRootHasStableArrays(t *testing.T) {
	res, err := Run(context.Background(), Options{Scan: scan.Options{Roots: []string{t.TempDir()}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files == nil || res.Edges == nil || res.Groups == nil || res.Entries == nil || res.Warnings == nil {
		t.Errorf("nil arrays in %+v", res)
	}
}

// staleStore ignores its validator, like a cache whose entry survived a
// rewrite with a restored mtime on a platform without ctime.
type staleStore struct{ m map[string][]byte }

func (s *staleStore) Get(bucket, key string, _ cache.Validator, out any) (bool, error) {
	raw, ok := s.m[bucket+key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, out)
}
func (s *staleStore) Put(bucket, key string, _ cache.Validator, _ string, payload any) error {
	raw, err := json.Marshal(payload)
	s.m[bucket+key] = raw
	return err
}
func (s *staleStore) Close() error     { return nil }
func (s *staleStore) Enabled() bool    { return true }
func (s *staleStore) Location() string { return "stale" }

func TestStaleCacheNeverYieldsByteIdentical(t *testing.T) {
	for _, name := range []string{"bolt", "stale"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			a, b := filepath.Join(dir, "r", "a.mp4"), filepath.Join(dir, "r", "b.mp4")
			write(t, a, "same-content")
			write(t, b, "same-content")
			var store cache.Store = &staleStore{m: map[string][]byte{}}
			if name == "bolt" {
				s, err := cache.Open(filepath.Join(dir, "cache"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				store = s
			}
			opts := Options{Scan: scan.Options{Roots: []string{filepath.Join(dir, "r")}}, Mode: model.ModeExact, Cache: store}
			res, err := Run(context.Background(), opts)
			if err != nil || res.Stats.ByteIdenticalEdges != 1 {
				t.Fatalf("first scan: %v %+v", err, res.Stats)
			}
			st, _ := os.Stat(b)
			write(t, b, "diff-content")
			if err := os.Chtimes(b, st.ModTime(), st.ModTime()); err != nil {
				t.Fatal(err)
			}
			res, err = Run(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.Stats.ByteIdenticalEdges != 0 {
				t.Fatalf("stale cache produced a byte_identical edge: %+v", res.Edges)
			}
		})
	}
}

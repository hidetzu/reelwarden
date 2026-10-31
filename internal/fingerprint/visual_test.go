package fingerprint

import (
	"context"
	"errors"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
)

func TestDHash(t *testing.T) {
	px := make([]byte, 72)
	for y := 0; y < 8; y++ {
		for x := 0; x < 9; x++ {
			px[y*9+x] = byte(200 - x*20) // strictly decreasing: every bit set
		}
	}
	if h := DHash(px, 9, 8); h != ^uint64(0) {
		t.Errorf("decreasing rows: %016x", h)
	}
	for i := range px {
		px[i] = byte(i % 9 * 20) // increasing: no bits
	}
	if h := DHash(px, 9, 8); h != 0 {
		t.Errorf("increasing rows: %016x", h)
	}
	if Hamming(0, ^uint64(0)) != 64 || Hamming(0b1011, 0b0001) != 2 {
		t.Error("hamming")
	}
}

func TestSampleTimesDependOnlyOnDuration(t *testing.T) {
	ts := SampleTimes(16, 4)
	want := []float64{2, 6, 10, 14}
	for i := range ts {
		if ts[i] != want[i] {
			t.Fatalf("got %v want %v", ts, want)
		}
	}
}

type fakeExtractor struct {
	frames map[int][]byte // by sample index derived from time
	dur    float64
	n      int
	err    error
}

func (f *fakeExtractor) Version() string { return "fake" }
func (f *fakeExtractor) ExtractAudio(context.Context, string, float64, int) ([]byte, error) {
	return nil, nil
}
func (f *fakeExtractor) ExtractRGB(_ context.Context, _ string, at float64, _, w, h int) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := int(at / f.dur * float64(f.n))
	return grayRGB(f.frames[i]), nil
}

// grayRGB expands a gray frame to RGB with R=G=B.
func grayRGB(px []byte) []byte {
	if px == nil {
		return nil
	}
	out := make([]byte, 0, len(px)*3)
	for _, v := range px {
		out = append(out, v, v, v)
	}
	return out
}

func TestComputeVisualLowInfoAndFailures(t *testing.T) {
	p := DefaultVisualParams()
	p.Samples = 4
	black := make([]byte, 72)
	textured := make([]byte, 72)
	for i := range textured {
		textured[i] = byte((i * 37) % 251)
	}
	ex := &fakeExtractor{dur: 8, n: 4, frames: map[int][]byte{0: black, 1: textured, 2: nil, 3: textured}}
	mi := &model.MediaInfo{DurationSec: 8, DurationKnown: true, Streams: []model.StreamInfo{{Index: 0, Type: "video"}}}
	fp, err := ComputeVisual(context.Background(), ex, "x", mi, p)
	if err != nil {
		t.Fatal(err)
	}
	if fp.LowInfoCount != 1 || fp.FailedCount != 1 || fp.InformativeCount() != 2 {
		t.Errorf("low=%d failed=%d informative=%d", fp.LowInfoCount, fp.FailedCount, fp.InformativeCount())
	}
	ex.err = errors.New("boom")
	if _, err := ComputeVisual(context.Background(), ex, "x", mi, p); err == nil {
		t.Error("all frames failing must be an error")
	}
	if _, err := ComputeVisual(context.Background(), ex, "x", &model.MediaInfo{DurationKnown: true, DurationSec: 3}, p); !errors.Is(err, ErrNoVideo) {
		t.Errorf("want ErrNoVideo, got %v", err)
	}
	mi.DurationKnown = false
	if _, err := ComputeVisual(context.Background(), ex, "x", mi, p); !errors.Is(err, ErrNoDuration) {
		t.Errorf("want ErrNoDuration, got %v", err)
	}
}

func TestParamsKeyChangesWithSampling(t *testing.T) {
	a := DefaultVisualParams()
	b := a
	b.Samples = 24
	if ParamsKey(a) == ParamsKey(b) {
		t.Error("params key must change with sample count")
	}
}

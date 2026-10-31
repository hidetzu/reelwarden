package fingerprint

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/hidetzu/reelwarden/internal/media"
	"github.com/hidetzu/reelwarden/internal/model"
)

// VisualAlgorithmVersion is bumped whenever frame processing changes.
// v2: frames are read as RGB; luma feeds dHash and per-frame chroma is kept.
// v3: chroma is also kept per cell of a 3x3 grid.
const VisualAlgorithmVersion = 3

// DefaultVisualParams are the defaults recorded in docs/design.md §6.
func DefaultVisualParams() model.VisualParams {
	return model.VisualParams{
		Algorithm:        "dhash64",
		AlgorithmVersion: VisualAlgorithmVersion,
		Samples:          16,
		Width:            9,
		Height:           8,
		LowInfoStdDev:    6,
		LowInfoMean:      8,
	}
}

// ParamsKey serialises the parameters that invalidate cached fingerprints.
func ParamsKey(p model.VisualParams) string {
	return fmt.Sprintf("%s/v%d/n%d/%dx%d/sd%s/m%s", p.Algorithm, p.AlgorithmVersion, p.Samples, p.Width, p.Height,
		strconv.FormatFloat(p.LowInfoStdDev, 'g', -1, 64), strconv.FormatFloat(p.LowInfoMean, 'g', -1, 64))
}

// ErrNoVideo means the file has no decodable primary video stream.
var ErrNoVideo = errors.New("no video stream")

// ErrNoDuration means the duration is unknown, so samples cannot be placed.
var ErrNoDuration = errors.New("duration unknown")

// SampleTimes returns the evenly spaced sample grid, a function of duration only.
func SampleTimes(duration float64, n int) []float64 {
	ts := make([]float64, n)
	for i := 0; i < n; i++ {
		ts[i] = (float64(i) + 0.5) / float64(n) * duration
	}
	return ts
}

// ComputeVisual samples frames and hashes them. Individual frame failures
// are recorded, not fatal; if every frame fails an error is returned.
func ComputeVisual(ctx context.Context, ex media.FrameExtractor, path string, mi *model.MediaInfo, p model.VisualParams) (*model.VisualFingerprint, error) {
	v := mi.PrimaryVideo()
	if v == nil {
		return nil, ErrNoVideo
	}
	if !mi.DurationKnown || mi.DurationSec <= 0 {
		return nil, ErrNoDuration
	}
	fp := &model.VisualFingerprint{Params: p, FFmpegVersion: ex.Version()}
	var lastErr error
	for i, ts := range SampleTimes(mi.DurationSec, p.Samples) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fs := model.FrameSample{Index: i, TimeSec: math.Round(ts*1000) / 1000}
		rgb, err := ex.ExtractRGB(ctx, path, ts, v.Index, p.Width, p.Height)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		}
		if err != nil || rgb == nil {
			fs.Failed = true
			fp.FailedCount++
		} else {
			px := lumaAndChroma(rgb, p.Width, p.Height, &fs)
			fs.DHash = DHash(px, p.Width, p.Height)
			fs.Mean, fs.StdDev = meanStd(px)
			fs.LowInfo = fs.StdDev < p.LowInfoStdDev || fs.Mean < p.LowInfoMean
			if fs.LowInfo {
				fp.LowInfoCount++
			}
		}
		fp.Frames = append(fp.Frames, fs)
	}
	if fp.FailedCount == len(fp.Frames) {
		if lastErr == nil {
			lastErr = errors.New("no frames could be decoded")
		}
		return nil, fmt.Errorf("frame extraction failed: %w", lastErr)
	}
	return fp, nil
}

// DHash computes the horizontal-gradient difference hash of a w x h gray
// image: bit (y*(w-1)+x) is set when px[x] > px[x+1]. For 9x8 this yields
// 64 bits.
func DHash(px []byte, w, h int) uint64 {
	var hash uint64
	bit := 0
	for y := 0; y < h; y++ {
		row := px[y*w : (y+1)*w]
		for x := 0; x < w-1 && bit < 64; x++ {
			if row[x] > row[x+1] {
				hash |= 1 << uint(bit)
			}
			bit++
		}
	}
	return hash
}

// ColorGrid is the number of cells per side over which chroma is averaged.
const ColorGrid = 3

// lumaAndChroma converts packed w x h RGB to BT.601 full-range luma for
// dHash and stores colour features in fs: mean Cb/Cr and mean chroma
// magnitude of the frame, and mean Cb/Cr per cell of a ColorGrid grid. A
// greyscale or hue-shifted copy keeps its luma but not its chroma; the grid
// catches a hue rotation of a picture whose colours average out to grey.
func lumaAndChroma(rgb []byte, w, h int, fs *model.FrameSample) []byte {
	n := len(rgb) / 3
	px := make([]byte, n)
	var sumCb, sumCr, sumMag float64
	cells := ColorGrid * ColorGrid
	cellCb, cellCr, cellN := make([]float64, cells), make([]float64, cells), make([]float64, cells)
	for i := 0; i < n; i++ {
		r, g, b := float64(rgb[3*i]), float64(rgb[3*i+1]), float64(rgb[3*i+2])
		px[i] = byte(math.Round(0.299*r + 0.587*g + 0.114*b))
		cb := -0.168736*r - 0.331264*g + 0.5*b
		cr := 0.5*r - 0.418688*g - 0.081312*b
		sumCb += cb
		sumCr += cr
		sumMag += math.Hypot(cb, cr)
		if w > 0 && h > 0 {
			c := (i/w)*ColorGrid/h*ColorGrid + (i%w)*ColorGrid/w
			cellCb[c] += cb
			cellCr[c] += cr
			cellN[c]++
		}
	}
	round := func(v float64) float64 { return math.Round(v*100) / 100 }
	if n > 0 {
		fs.Cb = round(sumCb / float64(n))
		fs.Cr = round(sumCr / float64(n))
		fs.Chroma = round(sumMag / float64(n))
	}
	if w > 0 && h > 0 {
		fs.CellCbCr = make([]float64, 0, 2*cells)
		for c := 0; c < cells; c++ {
			if cellN[c] == 0 {
				fs.CellCbCr = append(fs.CellCbCr, 0, 0)
				continue
			}
			fs.CellCbCr = append(fs.CellCbCr, round(cellCb[c]/cellN[c]), round(cellCr[c]/cellN[c]))
		}
	}
	return px
}

func meanStd(px []byte) (float64, float64) {
	if len(px) == 0 {
		return 0, 0
	}
	var sum float64
	for _, b := range px {
		sum += float64(b)
	}
	mean := sum / float64(len(px))
	var ss float64
	for _, b := range px {
		d := float64(b) - mean
		ss += d * d
	}
	return math.Round(mean*100) / 100, math.Round(math.Sqrt(ss/float64(len(px)))*100) / 100
}

// Hamming returns the number of differing bits.
func Hamming(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}

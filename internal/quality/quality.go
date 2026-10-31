// Package quality summarises media information into comparable profiles
// and compares two profiles with explicit, rule-based reasons (docs/design.md §9).
// It never produces a single opaque score.
package quality

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/hidetzu/reelwarden/internal/model"
)

// Profile is the comparable summary of one file's media.
type Profile struct {
	Known          bool
	Width, Height  int // after rotation
	Pixels         int
	Codec          string
	BitDepth       int
	PixelFormat    string
	VideoBitRate   int64 // stream bitrate, or container bitrate as fallback
	BitRateSource  string
	FrameRate      float64
	DurationSec    float64
	HDR            bool
	ColorTransfer  string
	VideoStreams   int
	AudioStreams   int
	AudioLanguages []string
	AudioCodecs    []string
	Subtitles      int
	SubLanguages   []string
	Chapters       int
	Attachments    int
	DataStreams    int
	DecodeProblems []string
}

// ProfileOf builds a profile from an entity. Missing data is left zero.
func ProfileOf(f *model.PhysicalFile) Profile {
	p := Profile{}
	mi := f.Media
	if mi == nil {
		return p
	}
	p.Known = true
	p.DurationSec = mi.DurationSec
	p.VideoStreams = mi.VideoStreams
	p.AudioStreams = mi.AudioStreams
	p.Subtitles = mi.SubtitleStreams
	p.Chapters = mi.Chapters
	p.Attachments = mi.Attachments
	p.DataStreams = mi.DataStreams
	if mi.ProbeError != "" {
		p.DecodeProblems = append(p.DecodeProblems, "ffprobe: "+mi.ProbeError)
	}
	if f.Visual != nil && f.Visual.FailedCount > 0 {
		p.DecodeProblems = append(p.DecodeProblems, fmt.Sprintf("%d sample frames failed to decode", f.Visual.FailedCount))
	}
	if v := mi.PrimaryVideo(); v != nil {
		p.Width, p.Height = v.Width, v.Height
		if v.Rotation == 90 || v.Rotation == 270 {
			p.Width, p.Height = v.Height, v.Width
		}
		p.Pixels = p.Width * p.Height
		p.Codec = v.Codec
		p.BitDepth = v.BitDepth
		p.PixelFormat = v.PixelFormat
		p.FrameRate = v.AvgFrameRate
		if p.FrameRate == 0 {
			p.FrameRate = v.FrameRate
		}
		p.HDR = v.HDR
		p.ColorTransfer = v.ColorTransfer
		if v.BitRate > 0 {
			p.VideoBitRate = v.BitRate
			p.BitRateSource = "stream"
		} else if mi.BitRate > 0 {
			p.VideoBitRate = mi.BitRate
			p.BitRateSource = "container"
		}
	}
	for _, s := range mi.Streams {
		switch s.Type {
		case "audio":
			p.AudioLanguages = append(p.AudioLanguages, langOf(s.Language))
			p.AudioCodecs = append(p.AudioCodecs, s.Codec)
		case "subtitle":
			p.SubLanguages = append(p.SubLanguages, langOf(s.Language))
		}
	}
	sort.Strings(p.AudioLanguages)
	sort.Strings(p.SubLanguages)
	return p
}

func langOf(s string) string {
	if s == "" {
		return "und"
	}
	return s
}

// Summary returns a one-line human description.
func (p Profile) Summary() string {
	if !p.Known {
		return "media info unavailable"
	}
	parts := []string{}
	if p.Pixels > 0 {
		parts = append(parts, fmt.Sprintf("%dx%d", p.Width, p.Height))
	} else {
		parts = append(parts, "no video")
	}
	if p.Codec != "" {
		parts = append(parts, strings.ToUpper(p.Codec))
	}
	if p.VideoBitRate > 0 {
		parts = append(parts, fmt.Sprintf("%.1f Mbps", float64(p.VideoBitRate)/1e6))
	}
	if p.FrameRate > 0 {
		parts = append(parts, fmt.Sprintf("%.3g fps", p.FrameRate))
	}
	if p.BitDepth > 0 {
		parts = append(parts, fmt.Sprintf("%d-bit", p.BitDepth))
	}
	if p.HDR {
		parts = append(parts, "HDR("+p.ColorTransfer+")")
	}
	parts = append(parts, fmt.Sprintf("%s", formatDuration(p.DurationSec)))
	parts = append(parts, fmt.Sprintf("audio: %d", p.AudioStreams))
	parts = append(parts, fmt.Sprintf("subs: %d", p.Subtitles))
	if p.Chapters > 0 {
		parts = append(parts, fmt.Sprintf("chapters: %d", p.Chapters))
	}
	return strings.Join(parts, " | ")
}

func formatDuration(s float64) string {
	if s <= 0 {
		return "duration ?"
	}
	t := int(math.Round(s))
	return fmt.Sprintf("%d:%02d:%02d", t/3600, t/60%60, t%60)
}

// Difference is a blocking difference that prevents automatic preference.
type Difference struct {
	Code   string
	Detail string
}

func (d Difference) String() string { return d.Code + ": " + d.Detail }

// BlockingDifferences lists stream-set and content differences that make
// any automatic keep decision unsafe.
func BlockingDifferences(a, b Profile) []Difference {
	var out []Difference
	add := func(code, f string, args ...any) { out = append(out, Difference{code, fmt.Sprintf(f, args...)}) }
	if a.VideoStreams != b.VideoStreams {
		add("video_track_count_differs", "%d vs %d video tracks", a.VideoStreams, b.VideoStreams)
	}
	if a.AudioStreams != b.AudioStreams {
		add("audio_track_count_differs", "%d vs %d audio tracks", a.AudioStreams, b.AudioStreams)
	} else if strings.Join(a.AudioLanguages, ",") != strings.Join(b.AudioLanguages, ",") {
		add("audio_languages_differ", "[%s] vs [%s]", strings.Join(a.AudioLanguages, ","), strings.Join(b.AudioLanguages, ","))
	}
	if a.Subtitles != b.Subtitles {
		add("subtitle_track_count_differs", "%d vs %d subtitle tracks", a.Subtitles, b.Subtitles)
	} else if strings.Join(a.SubLanguages, ",") != strings.Join(b.SubLanguages, ",") {
		add("subtitle_languages_differ", "[%s] vs [%s]", strings.Join(a.SubLanguages, ","), strings.Join(b.SubLanguages, ","))
	}
	if a.Chapters != b.Chapters {
		add("chapter_count_differs", "%d vs %d chapters", a.Chapters, b.Chapters)
	}
	// Attachment contents are not compared, so any attachment at all means
	// a copy might hold cover art, fonts or images the other lacks.
	if a.Attachments > 0 || b.Attachments > 0 {
		add("attachments_present", "%d vs %d attachments (cover art, fonts, images); contents are not compared", a.Attachments, b.Attachments)
	}
	// Subtitle text is not compared either: equal track counts and languages
	// can still hold different text.
	if a.Subtitles > 0 || b.Subtitles > 0 {
		add("subtitles_present", "%d vs %d subtitle tracks; their text is not compared", a.Subtitles, b.Subtitles)
	}
	if a.DataStreams != b.DataStreams {
		add("data_stream_count_differs", "%d vs %d data streams (telemetry, timecode)", a.DataStreams, b.DataStreams)
	}
	if a.HDR != b.HDR {
		add("hdr_sdr_differs", "HDR on one side only (%q vs %q)", a.ColorTransfer, b.ColorTransfer)
	}
	tol := math.Max(1.0, 0.005*math.Max(a.DurationSec, b.DurationSec))
	if d := math.Abs(a.DurationSec - b.DurationSec); d > tol {
		add("duration_differs", "%.2fs difference (tolerance %.2fs)", d, tol)
	}
	if len(a.DecodeProblems) > 0 || len(b.DecodeProblems) > 0 {
		add("decode_problems", "%s", strings.Join(append(append([]string{}, a.DecodeProblems...), b.DecodeProblems...), "; "))
	}
	return out
}

// Verdict is the outcome of comparing two profiles.
type Verdict int

const (
	// Undecided: no automatic preference.
	Undecided Verdict = iota
	// LeftBetter: left dominates right.
	LeftBetter
	// RightBetter: right dominates left.
	RightBetter
)

// Comparison is the result of Compare.
type Comparison struct {
	Verdict Verdict
	Code    string
	Reasons []string
}

// Thresholds for dominance.
const (
	PixelRatio   = 1.2
	BitRateRatio = 1.1
	FrameRatio   = 1.05
)

// Compare decides whether one profile dominates the other on video quality
// alone. It assumes BlockingDifferences was empty.
func Compare(a, b Profile) Comparison {
	if a.Pixels == 0 || b.Pixels == 0 {
		return Comparison{Code: "resolution_unknown", Reasons: []string{"resolution unknown on at least one side"}}
	}
	var c Comparison
	switch {
	case float64(a.Pixels) >= PixelRatio*float64(b.Pixels):
		c = Comparison{Verdict: LeftBetter, Code: "higher_resolution",
			Reasons: []string{fmt.Sprintf("higher resolution: %dx%d vs %dx%d", a.Width, a.Height, b.Width, b.Height)}}
	case float64(b.Pixels) >= PixelRatio*float64(a.Pixels):
		c = Comparison{Verdict: RightBetter, Code: "higher_resolution",
			Reasons: []string{fmt.Sprintf("higher resolution: %dx%d vs %dx%d", b.Width, b.Height, a.Width, a.Height)}}
	case a.Codec != b.Codec:
		return Comparison{Code: "codec_bitrate_not_comparable",
			Reasons: []string{fmt.Sprintf("similar resolution, different codecs (%s vs %s): bitrates are not comparable", a.Codec, b.Codec)}}
	case a.VideoBitRate == 0 || b.VideoBitRate == 0:
		return Comparison{Code: "bitrate_unknown", Reasons: []string{"similar resolution and codec, bitrate unknown"}}
	case float64(a.VideoBitRate) >= BitRateRatio*float64(b.VideoBitRate):
		c = Comparison{Verdict: LeftBetter, Code: "higher_bitrate_same_codec",
			Reasons: []string{fmt.Sprintf("same codec (%s) and resolution, higher bitrate: %.2f vs %.2f Mbps", a.Codec, float64(a.VideoBitRate)/1e6, float64(b.VideoBitRate)/1e6)}}
	case float64(b.VideoBitRate) >= BitRateRatio*float64(a.VideoBitRate):
		c = Comparison{Verdict: RightBetter, Code: "higher_bitrate_same_codec",
			Reasons: []string{fmt.Sprintf("same codec (%s) and resolution, higher bitrate: %.2f vs %.2f Mbps", a.Codec, float64(b.VideoBitRate)/1e6, float64(a.VideoBitRate)/1e6)}}
	default:
		return Comparison{Code: "no_quality_difference", Reasons: []string{"no meaningful difference in resolution or bitrate"}}
	}
	// The winner must not lose on frame rate or bit depth.
	w, l := a, b
	if c.Verdict == RightBetter {
		w, l = b, a
	}
	if w.FrameRate > 0 && l.FrameRate > 0 && l.FrameRate >= FrameRatio*w.FrameRate {
		return Comparison{Code: "frame_rate_conflict", Reasons: append(c.Reasons, fmt.Sprintf("but the other has a higher frame rate (%.3g vs %.3g fps)", l.FrameRate, w.FrameRate))}
	}
	if w.BitDepth > 0 && l.BitDepth > w.BitDepth {
		return Comparison{Code: "bit_depth_conflict", Reasons: append(c.Reasons, fmt.Sprintf("but the other has a higher bit depth (%d vs %d)", l.BitDepth, w.BitDepth))}
	}
	if w.Codec != l.Codec {
		c.Reasons = append(c.Reasons, fmt.Sprintf("codecs differ (%s vs %s); a higher resolution may still be an upscale", w.Codec, l.Codec))
	}
	return c
}

package media

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hidetzu/reelwarden/internal/model"
)

// ProbeAlgorithmVersion is bumped when MediaInfo derivation changes.
const ProbeAlgorithmVersion = 3

// Probe runs ffprobe and parses its JSON output.
func (t *Tools) Probe(ctx context.Context, path string) (*model.MediaInfo, error) {
	in, err := inputURL(path)
	if err != nil {
		return nil, err
	}
	out, stderr, err := run(ctx, t.Timeout, MaxProbeOutput, t.FFprobePath,
		"-hide_banner", "-v", "error",
		"-protocol_whitelist", "file",
		"-print_format", "json",
		"-show_format", "-show_streams", "-show_chapters", "-show_error",
		in)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(out) == 0 && err != nil {
		return nil, err
	}
	mi, perr := ParseProbe(out)
	if perr != nil {
		if err != nil {
			return nil, err
		}
		return nil, perr
	}
	if err != nil && mi.ProbeError == "" {
		mi.ProbeError = firstLine(stderr)
	}
	return mi, nil
}

type probeJSON struct {
	Streams  []probeStream  `json:"streams"`
	Format   *probeFormat   `json:"format"`
	Chapters []struct{}     `json:"chapters"`
	Error    *probeErrorObj `json:"error"`
}

type probeErrorObj struct {
	Code   int    `json:"code"`
	String string `json:"string"`
}

type probeFormat struct {
	FormatName     string `json:"format_name"`
	FormatLongName string `json:"format_long_name"`
	Duration       string `json:"duration"`
	BitRate        string `json:"bit_rate"`
}

type probeStream struct {
	Index            int               `json:"index"`
	CodecName        string            `json:"codec_name"`
	CodecType        string            `json:"codec_type"`
	Profile          string            `json:"profile"`
	Width            int               `json:"width"`
	Height           int               `json:"height"`
	PixFmt           string            `json:"pix_fmt"`
	BitsPerRawSample string            `json:"bits_per_raw_sample"`
	ColorPrimaries   string            `json:"color_primaries"`
	ColorTransfer    string            `json:"color_transfer"`
	ColorSpace       string            `json:"color_space"`
	RFrameRate       string            `json:"r_frame_rate"`
	AvgFrameRate     string            `json:"avg_frame_rate"`
	BitRate          string            `json:"bit_rate"`
	Duration         string            `json:"duration"`
	Channels         int               `json:"channels"`
	ChannelLayout    string            `json:"channel_layout"`
	SampleRate       string            `json:"sample_rate"`
	Disposition      map[string]int    `json:"disposition"`
	Tags             map[string]string `json:"tags"`
	SideDataList     []map[string]any  `json:"side_data_list"`
}

// ParseProbe converts ffprobe JSON into MediaInfo. Missing values stay zero
// and are treated as unknown downstream.
func ParseProbe(data []byte) (*model.MediaInfo, error) {
	var pj probeJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, fmt.Errorf("parse ffprobe output: %w", err)
	}
	mi := &model.MediaInfo{Streams: []model.StreamInfo{}}
	if pj.Error != nil {
		mi.ProbeError = pj.Error.String
	}
	if pj.Format != nil {
		mi.FormatName = pj.Format.FormatName
		mi.FormatLongName = pj.Format.FormatLongName
		if d, ok := parseFloat(pj.Format.Duration); ok && d > 0 {
			mi.DurationSec = d
			mi.DurationKnown = true
		}
		mi.BitRate, _ = parseInt(pj.Format.BitRate)
	}
	mi.Chapters = len(pj.Chapters)
	for _, ps := range pj.Streams {
		s := model.StreamInfo{
			Index:          ps.Index,
			Type:           ps.CodecType,
			Codec:          ps.CodecName,
			Profile:        ps.Profile,
			Width:          ps.Width,
			Height:         ps.Height,
			PixelFormat:    ps.PixFmt,
			ColorPrimaries: ps.ColorPrimaries,
			ColorTransfer:  ps.ColorTransfer,
			ColorSpace:     ps.ColorSpace,
			Channels:       ps.Channels,
			ChannelLayout:  ps.ChannelLayout,
			Language:       ps.Tags["language"],
			Title:          ps.Tags["title"],
			Default:        ps.Disposition["default"] == 1,
			Attached:       ps.Disposition["attached_pic"] == 1,
		}
		s.BitRate, _ = parseInt(ps.BitRate)
		if sr, ok := parseInt(ps.SampleRate); ok {
			s.SampleRate = int(sr)
		}
		s.FrameRate = parseRate(ps.RFrameRate)
		s.AvgFrameRate = parseRate(ps.AvgFrameRate)
		s.BitDepth = bitDepth(ps.BitsPerRawSample, ps.PixFmt)
		s.Rotation = rotation(ps)
		s.HDR = isHDR(ps.ColorTransfer) || hasHDRSideData(ps.SideDataList)
		switch ps.CodecType {
		case "video":
			if !s.Attached {
				mi.VideoStreams++
			} else {
				mi.Attachments++ // cover art
			}
		case "attachment":
			mi.Attachments++ // Matroska attachments (fonts, images)
		case "data":
			mi.DataStreams++ // telemetry (GoPro GPMF), timecode
		case "audio":
			mi.AudioStreams++
		case "subtitle":
			mi.SubtitleStreams++
		}
		if !mi.DurationKnown && ps.CodecType == "video" {
			if d, ok := parseFloat(ps.Duration); ok && d > 0 {
				mi.DurationSec = d
				mi.DurationKnown = true
			}
		}
		mi.Streams = append(mi.Streams, s)
	}
	return mi, nil
}

func parseFloat(s string) (float64, bool) {
	if s == "" || s == "N/A" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func parseInt(s string) (int64, bool) {
	if s == "" || s == "N/A" {
		return 0, false
	}
	i, err := strconv.ParseInt(s, 10, 64)
	return i, err == nil
}

func parseRate(s string) float64 {
	num, den, ok := strings.Cut(s, "/")
	if !ok {
		f, _ := parseFloat(s)
		return f
	}
	n, ok1 := parseFloat(num)
	d, ok2 := parseFloat(den)
	if !ok1 || !ok2 || d == 0 {
		return 0
	}
	return math.Round(n/d*1000) / 1000
}

func bitDepth(raw, pixFmt string) int {
	if v, ok := parseInt(raw); ok && v > 0 {
		return int(v)
	}
	switch {
	case pixFmt == "":
		return 0
	case strings.Contains(pixFmt, "16"):
		return 16
	case strings.Contains(pixFmt, "12"):
		return 12
	case strings.Contains(pixFmt, "10"):
		return 10
	case strings.HasPrefix(pixFmt, "yuv") || strings.HasPrefix(pixFmt, "nv12") || strings.HasPrefix(pixFmt, "gray") || strings.HasPrefix(pixFmt, "rgb") || strings.HasPrefix(pixFmt, "bgr"):
		return 8
	}
	return 0
}

func rotation(ps probeStream) int {
	for _, sd := range ps.SideDataList {
		if r, ok := sd["rotation"]; ok {
			if f, ok := r.(float64); ok {
				return normRotation(int(f))
			}
		}
	}
	if r, ok := parseInt(ps.Tags["rotate"]); ok {
		return normRotation(int(r))
	}
	return 0
}

func normRotation(r int) int {
	r %= 360
	if r < 0 {
		r += 360
	}
	return r
}

func isHDR(transfer string) bool {
	switch transfer {
	case "smpte2084", "arib-std-b67":
		return true
	}
	return false
}

func hasHDRSideData(list []map[string]any) bool {
	for _, sd := range list {
		t, _ := sd["side_data_type"].(string)
		lt := strings.ToLower(t)
		if strings.Contains(lt, "mastering display") || strings.Contains(lt, "content light level") || strings.Contains(lt, "dovi") || strings.Contains(lt, "dolby vision") {
			return true
		}
	}
	return false
}

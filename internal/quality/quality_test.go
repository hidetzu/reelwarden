package quality

import "testing"

func p(w, h int, codec string, br int64, fps float64, depth int) Profile {
	return Profile{Known: true, Width: w, Height: h, Pixels: w * h, Codec: codec, VideoBitRate: br, FrameRate: fps, BitDepth: depth, DurationSec: 100, VideoStreams: 1, AudioStreams: 1}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b Profile
		want Verdict
		code string
	}{
		{"resolution", p(1920, 1080, "h264", 8e6, 25, 8), p(1280, 720, "hevc", 3e6, 25, 8), LeftBetter, "higher_resolution"},
		{"resolution right", p(1280, 720, "h264", 8e6, 25, 8), p(1920, 1080, "h264", 3e6, 25, 8), RightBetter, "higher_resolution"},
		{"bitrate same codec", p(1920, 1080, "h264", 8e6, 25, 8), p(1920, 1080, "h264", 4e6, 25, 8), LeftBetter, "higher_bitrate_same_codec"},
		{"codec differs", p(1920, 1080, "h264", 8e6, 25, 8), p(1920, 1080, "hevc", 4e6, 25, 8), Undecided, "codec_bitrate_not_comparable"},
		{"no difference", p(1920, 1080, "h264", 8e6, 25, 8), p(1920, 1080, "h264", 7.8e6, 25, 8), Undecided, "no_quality_difference"},
		{"fps conflict", p(1920, 1080, "h264", 8e6, 30, 8), p(1280, 720, "h264", 3e6, 60, 8), Undecided, "frame_rate_conflict"},
		{"bit depth conflict", p(1920, 1080, "h264", 8e6, 25, 8), p(1280, 720, "hevc", 3e6, 25, 10), Undecided, "bit_depth_conflict"},
		{"unknown", Profile{}, p(1280, 720, "h264", 3e6, 25, 8), Undecided, "resolution_unknown"},
	}
	for _, c := range cases {
		got := Compare(c.a, c.b)
		if got.Verdict != c.want || got.Code != c.code {
			t.Errorf("%s: got %v/%s want %v/%s (%v)", c.name, got.Verdict, got.Code, c.want, c.code, got.Reasons)
		}
	}
}

func TestBlockingDifferences(t *testing.T) {
	a := p(1920, 1080, "h264", 8e6, 25, 8)
	b := a
	if d := BlockingDifferences(a, b); len(d) != 0 {
		t.Fatalf("identical: %v", d)
	}
	b.AudioStreams = 2
	b.HDR = true
	b.DurationSec = 130
	b.Chapters = 3
	codes := map[string]bool{}
	for _, d := range BlockingDifferences(a, b) {
		codes[d.Code] = true
	}
	for _, c := range []string{"audio_track_count_differs", "hdr_sdr_differs", "duration_differs", "chapter_count_differs"} {
		if !codes[c] {
			t.Errorf("missing %s in %v", c, codes)
		}
	}
	c := a
	c.AudioLanguages = []string{"eng"}
	a.AudioLanguages = []string{"jpn"}
	if d := BlockingDifferences(a, c); len(d) != 1 || d[0].Code != "audio_languages_differ" {
		t.Errorf("languages: %v", d)
	}
}

// A copy that alone carries cover art or attachments must not be dropped.
func TestAttachmentsDifferBlocks(t *testing.T) {
	// Same count but possibly different contents still blocks.
	for _, n := range [][2]int{{0, 1}, {1, 1}} {
		a, b := Profile{Known: true, Attachments: n[0]}, Profile{Known: true, Attachments: n[1]}
		found := false
		for _, d := range BlockingDifferences(a, b) {
			found = found || d.Code == "attachments_present"
		}
		if !found {
			t.Fatalf("%v attachments not blocking", n)
		}
	}
	a, b := Profile{Known: true, DataStreams: 1}, Profile{Known: true}
	found := false
	for _, d := range BlockingDifferences(a, b) {
		found = found || d.Code == "data_stream_count_differs"
	}
	if !found {
		t.Fatal("data stream difference not blocking")
	}
}

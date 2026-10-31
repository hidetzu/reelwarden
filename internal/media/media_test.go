package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hidetzu/reelwarden/internal/testutil"
)

const probeSample = `{
 "streams": [
  {"index":0,"codec_name":"hevc","codec_type":"video","width":3840,"height":2160,"pix_fmt":"yuv420p10le",
   "color_transfer":"smpte2084","color_primaries":"bt2020","r_frame_rate":"24000/1001","avg_frame_rate":"24000/1001",
   "bit_rate":"20000000","disposition":{"default":1,"attached_pic":0},
   "side_data_list":[{"side_data_type":"Display Matrix","rotation":-90}]},
  {"index":1,"codec_name":"mjpeg","codec_type":"video","width":600,"height":600,"disposition":{"attached_pic":1}},
  {"index":2,"codec_name":"eac3","codec_type":"audio","channels":6,"channel_layout":"5.1","sample_rate":"48000","tags":{"language":"jpn"}},
  {"index":3,"codec_name":"aac","codec_type":"audio","channels":2,"sample_rate":"48000","tags":{"language":"eng"}},
  {"index":4,"codec_name":"subrip","codec_type":"subtitle","tags":{"language":"eng"}}
 ],
 "chapters":[{},{}],
 "format":{"format_name":"matroska,webm","duration":"5400.5","bit_rate":"24000000"}
}`

func TestParseProbe(t *testing.T) {
	mi, err := ParseProbe([]byte(probeSample))
	if err != nil {
		t.Fatal(err)
	}
	if mi.VideoStreams != 1 || mi.AudioStreams != 2 || mi.SubtitleStreams != 1 || mi.Chapters != 2 {
		t.Errorf("counts %+v", mi)
	}
	if !mi.DurationKnown || mi.DurationSec != 5400.5 {
		t.Errorf("duration %v", mi.DurationSec)
	}
	v := mi.PrimaryVideo()
	if v == nil || v.Codec != "hevc" || !v.HDR || v.BitDepth != 10 || v.Rotation != 270 || v.FrameRate != 23.976 {
		t.Errorf("video %+v", v)
	}
}

func TestParseProbeMissingValues(t *testing.T) {
	mi, err := ParseProbe([]byte(`{"streams":[{"index":0,"codec_type":"video","codec_name":"h264","r_frame_rate":"0/0"}],"format":{"duration":"N/A"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if mi.DurationKnown || mi.PrimaryVideo().FrameRate != 0 {
		t.Errorf("%+v", mi)
	}
	if _, err := ParseProbe([]byte("not json")); err == nil {
		t.Error("expected parse error")
	}
}

func TestBoundedBuffer(t *testing.T) {
	b := &boundedBuffer{max: 10}
	b.Write([]byte("0123456789abcdef"))
	b.Write([]byte("more"))
	if !strings.HasPrefix(b.String(), "0123456789") || !b.truncated {
		t.Errorf("%q", b.String())
	}
}

func TestLocateMissing(t *testing.T) {
	_, err := Locate(context.Background(), filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err %v", err)
	}
}

func TestProbeAndExtractRealFFmpeg(t *testing.T) {
	testutil.FFmpeg(t)
	dir := t.TempDir()
	name := "http: concat 動画.mp4"
	if runtime.GOOS == "windows" {
		name = "concat 動画.mp4"
	}
	clip := filepath.Join(dir, name)
	testutil.Video(t, clip, "testsrc2", true)
	tools, err := Locate(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	mi, err := tools.Probe(context.Background(), clip)
	if err != nil {
		t.Fatal(err)
	}
	if mi.PrimaryVideo() == nil || mi.AudioStreams != 1 || !mi.DurationKnown {
		t.Fatalf("%+v", mi)
	}
	px, err := tools.ExtractRGB(context.Background(), clip, 3, mi.PrimaryVideo().Index, 9, 8)
	if err != nil || len(px) != 9*8*3 {
		t.Fatalf("extract: %v len=%d", err, len(px))
	}
	past, err := tools.ExtractRGB(context.Background(), clip, 9999, mi.PrimaryVideo().Index, 9, 8)
	if err != nil || past != nil {
		t.Errorf("past end should be nil frame: %v %v", past, err)
	}
	// ffprobe reports a missing file through its JSON "error" object.
	if mi, err := tools.Probe(context.Background(), filepath.Join(dir, "missing.mp4")); err == nil && mi.ProbeError == "" {
		t.Error("missing file should produce an error or ProbeError")
	}
}

func TestTimeout(t *testing.T) {
	testutil.FFmpeg(t)
	tools, err := Locate(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	// An infinite lavfi graph is not reachable through the file: protocol,
	// so use a real file with an absurdly short timeout instead.
	dir := t.TempDir()
	clip := filepath.Join(dir, "c.mp4")
	testutil.Video(t, clip, "testsrc2", false)
	tools.Timeout = time.Nanosecond
	if _, err := tools.Probe(context.Background(), clip); err == nil {
		t.Error("expected timeout")
	}
	os.Remove(clip)
}

func TestParseProbeCountsAttachments(t *testing.T) {
	mi, err := ParseProbe([]byte(`{"streams":[
		{"index":0,"codec_type":"video","codec_name":"h264","width":320,"height":180},
		{"index":1,"codec_type":"video","codec_name":"png","disposition":{"attached_pic":1}},
		{"index":2,"codec_type":"attachment","codec_name":"ttf"}],
		"format":{"duration":"10"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if mi.VideoStreams != 1 || mi.Attachments != 2 {
		t.Fatalf("video %d, attachments %d; want 1 and 2", mi.VideoStreams, mi.Attachments)
	}
}

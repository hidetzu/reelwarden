package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/testutil"
)

// With real FFmpeg: a lower-resolution copy with the same soundtrack may be
// proposed under balanced; the same picture with another soundtrack, or
// with none, must not be.
func TestBalancedComparesSoundtracks(t *testing.T) {
	testutil.FFmpeg(t)
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib")
	old := filepath.Join(dir, "old")
	orig := filepath.Join(lib, "orig.mp4")
	testutil.Video(t, orig, "mandelbrot", true)
	os.MkdirAll(old, 0o755)
	sameSound := filepath.Join(old, "same-sound.mp4")
	testutil.Transcode(t, orig, sameSound, "-vf", "scale=160:90", "-c:v", "mpeg4", "-q:v", "8", "-c:a", "copy")
	otherSound := filepath.Join(old, "other-sound.mp4")
	testutil.Gen(t, "-i", orig, "-f", "lavfi", "-i", "sine=frequency=660:duration="+testutil.Dur,
		"-map", "0:v", "-map", "1:a", "-vf", "scale=160:90", "-c:v", "mpeg4", "-q:v", "8", "-c:a", "aac", "-shortest", otherSound)
	noSound := filepath.Join(old, "no-sound.mp4")
	testutil.Transcode(t, orig, noSound, "-vf", "scale=160:90", "-c:v", "mpeg4", "-q:v", "8", "-an")

	// One scan per variant: a reviewed member in the same group would make
	// the keeper unconfirmed and hide the candidate being tested.
	decide := func(member string) model.MemberDecision {
		t.Helper()
		only := filepath.Join(dir, "only-"+filepath.Base(member))
		os.MkdirAll(only, 0o755)
		testutil.CopyFile(t, member, filepath.Join(only, filepath.Base(member)))
		scanFile := filepath.Join(dir, filepath.Base(member)+".json")
		if code, _, errs := run(t, "scan", "-q", "--no-cache", "--mode", "video", "--protect-root", lib, "-o", scanFile, lib, only); code != 0 {
			t.Fatalf("scan: exit %d %s", code, errs)
		}
		code, out, errs := run(t, "report", "--format", "json", "--policy", "balanced", scanFile)
		if code != 0 {
			t.Fatalf("report: exit %d %s", code, errs)
		}
		var rep struct {
			Evaluation model.Evaluation `json:"evaluation"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		for _, g := range rep.Evaluation.Groups {
			for _, m := range g.Members {
				if filepath.Base(m.Path) == filepath.Base(member) {
					return m
				}
			}
		}
		return model.MemberDecision{Decision: "not grouped"}
	}
	if d := decide(sameSound); d.Decision != model.DecisionRedundantCandidate {
		t.Errorf("same soundtrack, lower resolution: %+v", d)
	}
	for m, reason := range map[string]string{otherSound: "audio_content_differs", noSound: "audio_track_count_differs"} {
		d := decide(m)
		if d.Decision == model.DecisionRedundantCandidate || !strings.Contains(strings.Join(d.Reasons, " "), reason) {
			t.Errorf("%s: want review for %s: %+v", filepath.Base(m), reason, d)
		}
	}
}

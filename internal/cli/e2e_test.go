package cli_test

// End-to-end tests over a synthetic library generated with FFmpeg. They map
// to the mandatory test cases of the development brief (numbers in
// comments). Tests that need FFmpeg skip when it is not on PATH.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hidetzu/reelwarden/internal/cli"
	"github.com/hidetzu/reelwarden/internal/filesystem"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/testutil"
)

type lib struct {
	root string
	p    map[string]string // logical name -> path
	err  error
}

var (
	libOnce sync.Once
	theLib  *lib
	libDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if libDir != "" {
		os.RemoveAll(libDir)
	}
	os.Exit(code)
}

// specialName exercises shell metacharacters and non-ASCII text.
func specialName() string {
	if runtime.GOOS == "windows" {
		return "動画 $(touch PWNED) & echo; 'q'.mp4"
	}
	return "動画 $(touch PWNED) & echo; 'q' \"dq\".mp4"
}

// library builds the shared fixture tree once.
func library(t *testing.T) *lib {
	t.Helper()
	testutil.FFmpeg(t)
	libOnce.Do(func() {
		dir, err := os.MkdirTemp("", "reelwarden-e2e-")
		if err != nil {
			theLib = &lib{err: err}
			return
		}
		libDir = dir
		l := &lib{root: dir, p: map[string]string{}}
		j := func(parts ...string) string { return filepath.Join(append([]string{dir}, parts...)...) }
		l.p["orig"] = j("A", "__files", "orig.mp4")
		testutil.Video(t, l.p["orig"], "testsrc2", true)
		// 5: three hard links to one entity. 6: a symlink to it.
		l.p["hl1"] = j("A", "keyword1", "orig-link.mp4")
		l.p["hl2"] = j("A", "keyword2", "renamed.mp4")
		for _, k := range []string{"hl1", "hl2"} {
			os.MkdirAll(filepath.Dir(l.p[k]), 0o755)
			if err := os.Link(l.p["orig"], l.p[k]); err != nil {
				theLib = &lib{err: err}
				return
			}
		}
		l.p["sym"] = j("A", "keyword3", "shortcut.mp4")
		os.MkdirAll(filepath.Dir(l.p["sym"]), 0o755)
		if err := os.Symlink(filepath.Join("..", "__files", "orig.mp4"), l.p["sym"]); err != nil {
			delete(l.p, "sym") // Windows without symlink privilege
		}
		// 1, 13: byte copy with a different name, extension and non-ASCII path.
		l.p["copy"] = j("B", "archive", "同じ バイト.mov")
		testutil.CopyFile(t, l.p["orig"], l.p["copy"])
		// 2: re-encode. 3: lower resolution. Different codec.
		l.p["reenc"] = j("B", "archive", "reencode.mp4")
		testutil.Transcode(t, l.p["orig"], l.p["reenc"], "-c:v", "mpeg4", "-q:v", "15", "-c:a", "copy")
		l.p["lowres"] = j("B", "archive", "lowres.mkv")
		testutil.Transcode(t, l.p["orig"], l.p["lowres"], "-vf", "scale=160:90", "-c:v", "mpeg4", "-c:a", "copy")
		l.p["mpeg2"] = j("B", "archive", "mpeg2.mkv")
		testutil.Transcode(t, l.p["orig"], l.p["mpeg2"], "-c:v", "mpeg2video", "-q:v", "4", "-c:a", "copy")
		// 4: same name, different content.
		l.p["samename"] = j("C", "orig.mp4")
		testutil.Video(t, l.p["samename"], "mandelbrot", true)
		// 9: same intro, different main content.
		l.p["introA"] = j("C", "intro-a.mp4")
		testutil.SharedIntro(t, l.p["introA"], "mandelbrot")
		l.p["introB"] = j("C", "intro-b.mp4")
		testutil.SharedIntro(t, l.p["introB"], "sierpinski")
		// 10: audio track missing; subtitle track added.
		l.p["noaudio"] = j("C", "noaudio.mp4")
		testutil.Transcode(t, l.p["orig"], l.p["noaudio"], "-an", "-c:v", "copy")
		srt := j("srt", "subs.srt")
		os.MkdirAll(filepath.Dir(srt), 0o755)
		os.WriteFile(srt, []byte("1\n00:00:01,000 --> 00:00:04,000\nhello\n"), 0o644)
		l.p["subs"] = j("C", "withsubs.mkv")
		testutil.Gen(t, "-i", l.p["orig"], "-i", srt, "-map", "0", "-map", "1", "-c", "copy", "-c:s", "srt", l.p["subs"])
		// Low-information videos must never match each other.
		l.p["black1"] = j("D", "black1.mp4")
		testutil.Video(t, l.p["black1"], "black", false)
		l.p["black2"] = j("D", "black2.mp4")
		testutil.Video(t, l.p["black2"], "black", false, "-vf", "scale=256:144")
		// 12: broken video.
		l.p["broken"] = j("D", "broken.mp4")
		os.WriteFile(l.p["broken"], bytes.Repeat([]byte("not a video "), 5000), 0o644)
		// 13: special characters (a different video so it is not grouped).
		l.p["special"] = j("D", specialName())
		testutil.Video(t, l.p["special"], "sierpinski", false)
		theLib = l
	})
	if theLib.err != nil {
		t.Fatalf("fixture library: %v", theLib.err)
	}
	return theLib
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(context.Background(), args, cli.IO{Out: &out, Err: &errb})
	return code, out.String(), errb.String()
}

func scanJSON(t *testing.T, args ...string) (*model.ScanResult, int, string) {
	t.Helper()
	code, out, errs := run(t, append([]string{"scan", "-q", "--no-cache"}, args...)...)
	var r model.ScanResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("scan output not JSON (exit %d): %v\nstderr: %s", code, err, errs)
	}
	return &r, code, errs
}

func fileOf(r *model.ScanResult, path string) *model.PhysicalFile {
	for i := range r.Files {
		for _, kp := range r.Files[i].KnownPaths {
			if kp == path {
				return &r.Files[i]
			}
		}
	}
	return nil
}

func relation(r *model.ScanResult, a, b string) string {
	fa, fb := fileOf(r, a), fileOf(r, b)
	if fa == nil || fb == nil {
		return "missing"
	}
	if fa.ID == fb.ID {
		return model.RelationSameFileAlias
	}
	for _, e := range r.Edges {
		if (e.Left == fa.ID && e.Right == fb.ID) || (e.Left == fb.ID && e.Right == fa.ID) {
			return e.Relation
		}
	}
	return "none"
}

var videoScan struct {
	once sync.Once
	res  *model.ScanResult
	code int
}

func videoResult(t *testing.T) (*model.ScanResult, *lib) {
	t.Helper()
	l := library(t)
	videoScan.once.Do(func() {
		videoScan.res, videoScan.code, _ = scanJSON(t, "--mode", "video", "--protect-root", filepath.Join(l.root, "A", "__files"),
			filepath.Join(l.root, "A"), filepath.Join(l.root, "B"), filepath.Join(l.root, "C"), filepath.Join(l.root, "D"))
	})
	return videoScan.res, l
}

// Accuracy table: fixed expected pairs, with FP/FN accounting.
func TestVisualAccuracyDataset(t *testing.T) {
	r, l := videoResult(t)
	type pair struct {
		a, b string
		want string
		why  string
	}
	pairs := []pair{
		{"orig", "copy", model.RelationByteIdentical, "1: same bytes, different name"},
		{"orig", "hl1", model.RelationSameFileAlias, "5: hard link"},
		{"orig", "reenc", model.RelationVisuallySimilar, "2: re-encode"},
		{"orig", "lowres", model.RelationVisuallySimilar, "3: 320x180 vs 160x90"},
		{"orig", "mpeg2", model.RelationVisuallySimilar, "codec change"},
		{"orig", "noaudio", model.RelationVisuallySimilar, "10: same video, no audio"},
		{"orig", "subs", model.RelationVisuallySimilar, "10: same video, extra subtitle"},
		{"orig", "samename", "none", "4: same name, different content"},
		{"introA", "introB", "uncertain|none", "9: shared intro only"},
		{"introA", "samename", "none", "9: intro + mandelbrot vs mandelbrot from t=0"},
		{"black1", "black2", "none", "low-information frames only"},
		{"orig", "special", "none", "different content"},
	}
	fp, fn := 0, 0
	for _, p := range pairs {
		got := relation(r, l.p[p.a], l.p[p.b])
		ok := false
		for _, w := range strings.Split(p.want, "|") {
			if got == w {
				ok = true
			}
		}
		if !ok {
			wantMatch := p.want != "none" && p.want != "uncertain|none"
			if wantMatch {
				fn++
			} else {
				fp++
			}
			t.Errorf("%s ~ %s: got %s, want %s (%s)", p.a, p.b, got, p.want, p.why)
		}
	}
	t.Logf("accuracy dataset: %d pairs, false positives %d, false negatives %d", len(pairs), fp, fn)
	// No visually_similar edge may touch content that differs.
	for _, k := range []string{"samename", "introA", "introB", "black1", "black2", "special", "broken"} {
		f := fileOf(r, l.p[k])
		if f == nil {
			continue
		}
		for _, e := range r.Edges {
			if (e.Left == f.ID || e.Right == f.ID) && (e.Relation == model.RelationVisuallySimilar || e.Relation == model.RelationByteIdentical) {
				t.Errorf("unexpected %s edge on %s: %+v", e.Relation, k, e)
			}
		}
	}
}

// 5, 6: links counted once, all paths recorded.
func TestHardlinksAndSymlinksInVideoScan(t *testing.T) {
	r, l := videoResult(t)
	f := fileOf(r, l.p["orig"])
	if f == nil {
		t.Fatal("orig missing")
	}
	if len(f.KnownPaths) != 3 {
		t.Errorf("known paths %v", f.KnownPaths)
	}
	if _, ok := l.p["sym"]; ok && len(f.SymlinkRefs) != 1 {
		t.Errorf("symlink refs %v", f.SymlinkRefs)
	}
	if f.UnverifiedExternalLinks {
		t.Errorf("all links are inside the roots")
	}
	n := 0
	for _, x := range r.Files {
		if x.Size == f.Size && x.Exact != nil && f.Exact != nil && x.Exact.SHA256 == f.Exact.SHA256 {
			n++
		}
	}
	if n != 2 { // orig entity + byte copy
		t.Errorf("entities with orig content = %d, want 2", n)
	}
}

// 12: broken video reported, scan partial, no matches.
func TestBrokenVideoIsPartialFailure(t *testing.T) {
	r, l := videoResult(t)
	if videoScan.code != cli.ExitPartial || r.Status != model.StatusPartial {
		t.Errorf("exit %d status %s, want partial", videoScan.code, r.Status)
	}
	f := fileOf(r, l.p["broken"])
	if f == nil || len(f.Errors) == 0 || f.Visual != nil {
		t.Errorf("broken: %+v", f)
	}
}

// 13: special characters handled without shell interpretation.
func TestSpecialCharacterPaths(t *testing.T) {
	r, l := videoResult(t)
	f := fileOf(r, l.p["special"])
	if f == nil || f.Media == nil || f.Visual == nil {
		t.Fatalf("special path not processed: %+v", f)
	}
	for _, dir := range []string{".", l.root, filepath.Join(l.root, "D")} {
		if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
			t.Fatalf("shell injection: PWNED created in %s", dir)
		}
	}
}

// 3, 10: report shows quality reasons; track differences block automatic preference.
func TestReportDecisions(t *testing.T) {
	_, l := videoResult(t)
	scanFile := filepath.Join(t.TempDir(), "scan.json")
	code, _, errs := run(t, "scan", "-q", "--no-cache", "--mode", "video", "--protect-root", filepath.Join(l.root, "A", "__files"),
		"-o", scanFile, filepath.Join(l.root, "A"), filepath.Join(l.root, "B"), filepath.Join(l.root, "C"))
	if code != 0 {
		t.Fatalf("scan exit %d: %s", code, errs)
	}
	code, out, errs := run(t, "report", "--format", "json", "--policy", "balanced", scanFile)
	if code != 0 {
		t.Fatalf("report exit %d: %s", code, errs)
	}
	var doc struct {
		Evaluation model.Evaluation `json:"evaluation"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	dec := map[string]model.MemberDecision{}
	for _, g := range doc.Evaluation.Groups {
		for _, m := range g.Members {
			dec[m.Path] = m
		}
	}
	reasons := func(k string) string { return strings.Join(dec[l.p[k]].Reasons, " | ") }
	if d := dec[l.p["noaudio"]]; d.Decision != model.DecisionManualReview || !strings.Contains(reasons("noaudio"), "audio_track_count_differs") {
		t.Errorf("noaudio: %+v", d)
	}
	if d := dec[l.p["subs"]]; d.Decision != model.DecisionManualReview || !strings.Contains(reasons("subs"), "subtitle_track_count_differs") {
		t.Errorf("subs: %+v", d)
	}
	if d := dec[l.p["orig"]]; d.Decision == model.DecisionRedundantCandidate {
		t.Errorf("protected orig must never be redundant: %+v", d)
	}
	code, table, _ := run(t, "report", scanFile)
	if code != 0 || !strings.Contains(table, "No files were modified.") || !strings.Contains(table, "[hardlink]") {
		t.Errorf("table report:\n%s", table)
	}
	code, csvOut, _ := run(t, "report", "--format", "csv", scanFile)
	if code != 0 || !strings.Contains(csvOut, model.RelationSameFileAlias) {
		t.Errorf("csv report:\n%s", csvOut)
	}
	planFile := filepath.Join(t.TempDir(), "plan.json")
	if code, _, errs := run(t, "plan", "-o", planFile, scanFile); code != 0 {
		t.Fatalf("plan exit %d: %s", code, errs)
	}
	var p model.Plan
	b, _ := os.ReadFile(planFile)
	if err := json.Unmarshal(b, &p); err != nil || p.Executable {
		t.Fatalf("plan: %v %+v", err, p.Executable)
	}
}

// 16: no FFmpeg: exact works, video fails with exit 3.
func TestWithoutFFmpeg(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.mp4"), []byte("same"), 0o644)
	os.WriteFile(filepath.Join(dir, "b.mkv"), []byte("same"), 0o644)
	missing := filepath.Join(dir, "no-such-ffmpeg")
	code, _, errs := run(t, "scan", "-q", "--no-cache", "--mode", "video", "--ffmpeg-path", missing, "--ffprobe-path", missing, dir)
	if code != cli.ExitDependency || !strings.Contains(errs, "--mode exact works without it") {
		t.Errorf("video without ffmpeg: exit %d, stderr %q", code, errs)
	}
	r, code, _ := scanJSON(t, "--mode", "exact", dir)
	if code != 0 || len(r.Groups) != 1 || r.Groups[0].Relation != model.RelationByteIdentical {
		t.Errorf("exact without ffmpeg: exit %d groups %+v", code, r.Groups)
	}
	code, out, _ := run(t, "doctor", "--ffmpeg-path", missing, "--ffprobe-path", missing)
	if code != cli.ExitDependency || !strings.Contains(out, "exact mode: available") {
		t.Errorf("doctor: exit %d\n%s", code, out)
	}
}

// 11: same size, different content.
func TestSameSizeDifferentContent(t *testing.T) {
	dir := t.TempDir()
	a := bytes.Repeat([]byte("A"), 300_000)
	b := append([]byte(nil), a...)
	b[150_001+70_000] = 'B' // outside the sampled partial-hash regions
	os.WriteFile(filepath.Join(dir, "a.mp4"), a, 0o644)
	os.WriteFile(filepath.Join(dir, "b.mp4"), b, 0o644)
	r, code, _ := scanJSON(t, "--mode", "exact", dir)
	if code != 0 || len(r.Edges) != 0 || len(r.Groups) != 0 {
		t.Errorf("exit %d edges %+v", code, r.Edges)
	}
	if r.Stats.FullHashes != 2 {
		t.Errorf("partial hashes collide, so full hashes must be computed: %+v", r.Stats)
	}
}

// 8: hard link outside the roots.
func TestExternalHardlinkWarning(t *testing.T) {
	base := t.TempDir()
	in := filepath.Join(base, "root", "v.mp4")
	os.MkdirAll(filepath.Dir(in), 0o755)
	os.WriteFile(in, []byte("content"), 0o644)
	os.WriteFile(filepath.Join(base, "root", "copy.mp4"), []byte("content"), 0o644)
	if err := os.Link(in, filepath.Join(base, "outside.mp4")); err != nil {
		t.Skip(err)
	}
	r, _, _ := scanJSON(t, "--mode", "exact", filepath.Join(base, "root"))
	f := fileOf(r, in)
	if f == nil || !f.UnverifiedExternalLinks {
		t.Fatalf("expected unverified external links: %+v", f)
	}
	scanFile := filepath.Join(base, "scan.json")
	b, _ := json.Marshal(r)
	os.WriteFile(scanFile, b, 0o644)
	_, out, _ := run(t, "report", scanFile)
	if !strings.Contains(out, "not found among scanned paths") {
		t.Errorf("report must warn:\n%s", out)
	}
}

// 14: cache hit, then invalidation after parameter change.
func TestCacheHitAndInvalidation(t *testing.T) {
	l := library(t)
	cacheDir := t.TempDir()
	root := filepath.Join(l.root, "B")
	scan := func(samples string) *model.ScanResult {
		code, out, errs := run(t, "scan", "-q", "--mode", "video", "--cache-dir", cacheDir, "--samples", samples, root)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errs)
		}
		var r model.ScanResult
		json.Unmarshal([]byte(out), &r)
		return &r
	}
	first := scan("16")
	second := scan("16")
	if first.Stats.CacheHits != 0 || second.Stats.CacheHits == 0 {
		t.Errorf("cache hits first=%d second=%d", first.Stats.CacheHits, second.Stats.CacheHits)
	}
	for _, f := range second.Files {
		if f.Visual == nil || !f.Visual.FromCache {
			t.Errorf("visual not from cache: %s", f.PrimaryPath())
		}
	}
	third := scan("12")
	for _, f := range third.Files {
		if f.Visual == nil || f.Visual.FromCache || len(f.Visual.Frames) != 12 {
			t.Errorf("visual should be recomputed with 12 samples: %s", f.PrimaryPath())
		}
		if f.Media == nil || !f.Media.FromCache {
			t.Errorf("media info should still be cached: %s", f.PrimaryPath())
		}
	}
	if relation(first, filepath.Join(root, "archive", "reencode.mp4"), filepath.Join(root, "archive", "lowres.mkv")) !=
		relation(second, filepath.Join(root, "archive", "reencode.mp4"), filepath.Join(root, "archive", "lowres.mkv")) {
		t.Error("cached and uncached results differ")
	}
}

// 17: nothing under the roots changes, including links and mtimes.
func TestReadOnlyGuarantee(t *testing.T) {
	l := library(t)
	ident := func(p string, fi os.FileInfo) string {
		id := filesystem.IdentityOf(p, fi)
		return id.ID.Key()
	}
	before := testutil.Snapshot(t, l.root, ident)
	out := t.TempDir()
	scanFile := filepath.Join(out, "scan.json")
	run(t, "scan", "-q", "--cache-dir", filepath.Join(out, "cache"), "--mode", "video", "--follow-symlinks", "--protect-root", filepath.Join(l.root, "A", "__files"), "-o", scanFile, l.root)
	run(t, "report", scanFile)
	run(t, "report", "-f", "csv", "-o", filepath.Join(out, "r.csv"), scanFile)
	run(t, "plan", "--policy", "balanced", "-o", filepath.Join(out, "plan.json"), scanFile)
	run(t, "doctor")
	after := testutil.Snapshot(t, l.root, ident)
	if d := testutil.DiffSnapshots(before, after); len(d) > 0 {
		t.Fatalf("scanned tree changed:\n%s", strings.Join(d, "\n"))
	}
}

func TestOutputRefusesVideoExtension(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", filepath.Join(dir, "out.mp4"), dir)
	if code != cli.ExitUsage || !strings.Contains(errs, "video file extension") {
		t.Errorf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "out.mp4")); err == nil {
		t.Error("file must not be created")
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan"},
		{"scan", "--mode", "fast", "."},
		{"report", "--format", "xml", "x.json"},
		{"scan", "--bogus", "."},
	} {
		if code, _, _ := run(t, args...); code != cli.ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, cli.ExitUsage)
		}
	}
	if code, _, _ := run(t, "report", filepath.Join(t.TempDir(), "missing.json")); code != cli.ExitRuntime {
		t.Errorf("missing scan file: exit %d", code)
	}
}

package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/hidetzu/reelwarden/internal/model"
)

var t0 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type fopt func(*model.PhysicalFile)

func pf(id string, size int64, opts ...fopt) model.PhysicalFile {
	f := model.PhysicalFile{
		ID: id, IdentityStatus: model.IdentityKnown, IdentityConfidence: model.ConfidenceHigh,
		Identity: &model.FileIdentity{Device: 1, Inode: uint64(len(id) + int(id[len(id)-1]))},
		Nlink:    1, NlinkKnown: true, KnownPaths: []string{"/r/" + id + ".mp4"},
		Size: size, MTime: t0, Exact: &model.ExactFingerprint{SHA256: "ab"},
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

func video(w, h int, codec string, br int64, audio, subs int) fopt {
	return func(f *model.PhysicalFile) {
		mi := &model.MediaInfo{DurationSec: 600, DurationKnown: true, VideoStreams: 1, AudioStreams: audio, SubtitleStreams: subs}
		mi.Streams = append(mi.Streams, model.StreamInfo{Index: 0, Type: "video", Codec: codec, Width: w, Height: h, BitRate: br, AvgFrameRate: 25, BitDepth: 8})
		for i := 0; i < audio; i++ {
			mi.Streams = append(mi.Streams, model.StreamInfo{Index: 1 + i, Type: "audio", Codec: "aac", Language: "jpn"})
		}
		for i := 0; i < subs; i++ {
			mi.Streams = append(mi.Streams, model.StreamInfo{Index: 10 + i, Type: "subtitle", Codec: "srt", Language: "eng"})
		}
		f.Media = mi
		f.Visual = &model.VisualFingerprint{Params: model.VisualParams{AlgorithmVersion: 3}, Frames: make([]model.FrameSample, 16)}
		for i := range f.Visual.Frames {
			f.Visual.Frames[i].DHash = uint64(0xFF) << (8 * (i % 8)) // a moving picture
		}
	}
}

// still makes every sampled frame identical, like a slideshow or a static camera.
func still(f *model.PhysicalFile) {
	for i := range f.Visual.Frames {
		f.Visual.Frames[i].DHash = 0xF0F0
	}
}

func protected(f *model.PhysicalFile) {
	f.Protected = true
	f.ProtectedByRoot = "/r/__files"
	f.InProtectedLibrary = true
}
func hdr(f *model.PhysicalFile) {
	f.Media.Streams[0].HDR = true
	f.Media.Streams[0].ColorTransfer = "smpte2084"
}

func scanOf(rel string, files []model.PhysicalFile, edges [][2]string, edgeRel ...string) *model.ScanResult {
	r := &model.ScanResult{Status: model.StatusComplete, Files: files}
	g := model.DuplicateGroup{ID: "g0001", Relation: rel}
	for _, f := range files {
		g.Members = append(g.Members, f.ID)
	}
	for i, e := range edges {
		er := rel
		if i < len(edgeRel) {
			er = edgeRel[i]
		}
		id := "m" + string(rune('a'+i))
		me := model.MatchEdge{ID: id, Left: e[0], Right: e[1], Relation: er, Evidence: []string{"test"}}
		if er == model.RelationVisuallySimilar {
			me.Visual = &model.VisualMetrics{ComparableFrames: 16, MatchingFrames: 16, MatchRatio: 1}
		}
		r.Edges = append(r.Edges, me)
		g.Edges = append(g.Edges, id)
	}
	r.Groups = []model.DuplicateGroup{g}
	return r
}

func decisions(t *testing.T, ev *model.Evaluation) map[string]model.MemberDecision {
	t.Helper()
	out := map[string]model.MemberDecision{}
	for _, m := range ev.Groups[0].Members {
		out[m.FileID] = m
	}
	return out
}

func eval(t *testing.T, r *model.ScanResult, policy string) (*model.Evaluation, map[string]model.MemberDecision) {
	t.Helper()
	ev, err := Evaluate(r, policy)
	if err != nil {
		t.Fatal(err)
	}
	return ev, decisions(t, ev)
}

func hasReason(m model.MemberDecision, sub string) bool {
	for _, r := range m.Reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func TestByteIdenticalCandidate(t *testing.T) {
	a := pf("f1", 1000, protected, func(f *model.PhysicalFile) { f.KnownPaths = append(f.KnownPaths, "/r/k1/a.mp4"); f.Nlink = 2 })
	b := pf("f2", 1000)
	ev, d := eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), "")
	if d["f1"].Decision != model.DecisionRecommendedKeep || d["f2"].Decision != model.DecisionRedundantCandidate {
		t.Fatalf("%+v", d)
	}
	g := ev.Groups[0]
	if g.Action != model.ActionCandidate || g.Space.PotentialReclaimBytes != 1000 || g.Space.ReclaimStatus != model.ReclaimEstimated {
		t.Errorf("%+v", g)
	}
	if g.Space.LogicalBytes != 3000 || g.Space.PhysicalBytes != 2000 {
		t.Errorf("space %+v", g.Space)
	}
}

func TestProtectedIsKeeperAndNeverRedundant(t *testing.T) {
	a := pf("f1", 1000)
	b := pf("f2", 1000, protected)
	_, d := eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), "")
	if d["f2"].Decision != model.DecisionRecommendedKeep || d["f1"].Decision != model.DecisionRedundantCandidate {
		t.Fatalf("%+v", d)
	}
	c := pf("f3", 1000, protected)
	_, d = eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b, c}, [][2]string{{"f1", "f2"}, {"f1", "f3"}, {"f2", "f3"}}), "")
	if d["f2"].Decision != model.DecisionManualReview || d["f3"].Decision != model.DecisionManualReview {
		t.Fatalf("two protected must both be review: %+v", d)
	}
}

func TestUnverifiedExternalLinksBlocksCandidate(t *testing.T) {
	a := pf("f1", 1000)
	b := pf("f2", 1000, func(f *model.PhysicalFile) { f.Nlink = 3; f.UnverifiedExternalLinks = true })
	ev, d := eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), "")
	if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "unverified_external_links") {
		t.Fatalf("%+v", d["f2"])
	}
	if ev.Groups[0].Space.ReclaimStatus != model.ReclaimUnknown || ev.Groups[0].Space.PotentialReclaimBytes != 0 {
		t.Errorf("space %+v", ev.Groups[0].Space)
	}
}

func TestSymlinkRefsAndLowConfidenceBlockCandidate(t *testing.T) {
	a := pf("f1", 1000)
	b := pf("f2", 1000, func(f *model.PhysicalFile) { f.SymlinkRefs = []string{"/r/link.mp4"} })
	c := pf("f3", 1000, func(f *model.PhysicalFile) { f.IdentityConfidence = model.ConfidenceLow })
	_, d := eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b, c}, [][2]string{{"f1", "f2"}, {"f1", "f3"}, {"f2", "f3"}}), "")
	// f2 has the most references (path + symlink), so it becomes keeper.
	if d["f2"].Decision != model.DecisionRecommendedKeep {
		t.Fatalf("keeper: %+v", d)
	}
	if d["f3"].Decision != model.DecisionManualReview || !hasReason(d["f3"], "identity_confidence_low") {
		t.Errorf("f3 %+v", d["f3"])
	}
	_, d = eval(t, scanOf(model.RelationByteIdentical, []model.PhysicalFile{pf("f1", 1000, protected), b}, [][2]string{{"f1", "f2"}}), "")
	if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "referenced_by_symlinks") {
		t.Errorf("f2 %+v", d["f2"])
	}
}

func TestVisualResolutionPolicy(t *testing.T) {
	hi := pf("f1", 2000, video(1920, 1080, "h264", 8_000_000, 1, 0), protected)
	lo := pf("f2", 800, video(1280, 720, "hevc", 3_000_000, 1, 0))
	r := scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{lo, hi}, [][2]string{{"f1", "f2"}})
	ev, d := eval(t, r, model.PolicyConservative)
	if d["f1"].Decision != model.DecisionRecommendedKeep || d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "policy_conservative_visual") {
		t.Fatalf("conservative: %+v", d)
	}
	if ev.Groups[0].Action != model.ActionReview {
		t.Errorf("action %s", ev.Groups[0].Action)
	}
	_, d = eval(t, r, model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionRedundantCandidate || !hasReason(d["f2"], "higher resolution") {
		t.Fatalf("balanced: %+v", d)
	}
}

func TestVisualTrackDifferencesForceReview(t *testing.T) {
	cases := map[string][2]fopt{
		"audio_track_count_differs":    {video(1920, 1080, "h264", 8e6, 2, 0), video(1280, 720, "h264", 3e6, 1, 0)},
		"subtitle_track_count_differs": {video(1920, 1080, "h264", 8e6, 1, 0), video(1280, 720, "h264", 3e6, 1, 1)},
	}
	for code, o := range cases {
		hi := pf("f1", 2000, o[0])
		lo := pf("f2", 800, o[1])
		_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{hi, lo}, [][2]string{{"f1", "f2"}}), model.PolicyBalanced)
		if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], code) {
			t.Errorf("%s: f2 %+v", code, d["f2"])
		}
		if d["f1"].Decision != model.DecisionManualReview {
			t.Errorf("%s: keeper must not be asserted: %+v", code, d["f1"])
		}
	}
}

func TestHDRvsSDRForcesReview(t *testing.T) {
	a := pf("f1", 2000, video(3840, 2160, "hevc", 20e6, 1, 0))
	b := pf("f2", 2000, video(3840, 2160, "hevc", 18e6, 1, 0), hdr)
	_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), model.PolicyBalanced)
	for _, id := range []string{"f1", "f2"} {
		if d[id].Decision != model.DecisionManualReview {
			t.Errorf("%s %+v", id, d[id])
		}
	}
}

func TestSameResolutionDifferentCodecIsReview(t *testing.T) {
	a := pf("f1", 2000, video(1920, 1080, "h264", 8e6, 1, 0))
	b := pf("f2", 1000, video(1920, 1080, "hevc", 4e6, 1, 0))
	_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), model.PolicyBalanced)
	if !hasReason(d["f2"], "codec_bitrate_not_comparable") && !hasReason(d["f1"], "codec_bitrate_not_comparable") {
		t.Errorf("%+v", d)
	}
}

// A≈B, B≈C, A≉C: C must not become redundant against A.
func TestChainNoDirectEvidence(t *testing.T) {
	a := pf("fA", 3000, video(1920, 1080, "h264", 8e6, 1, 0), protected)
	b := pf("fB", 2000, video(1280, 720, "h264", 4e6, 1, 0))
	c := pf("fC", 1000, video(854, 480, "h264", 2e6, 1, 0))
	_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{a, b, c}, [][2]string{{"fA", "fB"}, {"fB", "fC"}}), model.PolicyBalanced)
	if d["fA"].Decision != model.DecisionRecommendedKeep {
		t.Fatalf("keeper %+v", d)
	}
	if d["fB"].Decision != model.DecisionRedundantCandidate {
		t.Errorf("B %+v", d["fB"])
	}
	if d["fC"].Decision != model.DecisionManualReview || !hasReason(d["fC"], "no_direct_evidence") {
		t.Errorf("C %+v", d["fC"])
	}
}

func TestMissingMediaIsInsufficientEvidence(t *testing.T) {
	a := pf("f1", 2000, video(1920, 1080, "h264", 8e6, 1, 0))
	b := pf("f2", 1000)
	_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}}), model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionInsufficientEvidence {
		t.Errorf("%+v", d["f2"])
	}
}

func TestUnknownPolicy(t *testing.T) {
	if _, err := Evaluate(&model.ScanResult{}, "aggressive"); err == nil {
		t.Error("expected error")
	}
}

func TestPlanCarriesPreconditionsAndWarnings(t *testing.T) {
	a := pf("f1", 1000)
	b := pf("f2", 1000, protected, func(f *model.PhysicalFile) {
		f.KnownPaths = []string{"/r/f2.mp4", "/r/k/f2.mp4"}
		f.Nlink = 2
	})
	r := scanOf(model.RelationByteIdentical, []model.PhysicalFile{a, b}, [][2]string{{"f1", "f2"}})
	ev, _ := Evaluate(r, "")
	p := BuildPlan(r, ev, "scan.json", model.ToolInfo{Name: "reelwarden"})
	if p.Executable || !strings.Contains(p.Notice, "does not implement apply") {
		t.Errorf("plan must be non-executable: %+v", p)
	}
	g := p.Groups[0]
	// f2 has more known paths, so it is the keeper; f1 is the candidate.
	if g.Keeper == nil || g.Keeper.FileID != "f2" || len(g.Actions) != 1 {
		t.Fatalf("%+v", g)
	}
	act := g.Actions[0]
	if act.Type != model.PlanActionCandidateRemove || len(act.Preconditions) != 1 || act.Preconditions[0].SHA256 == "" || !act.Irreversible {
		t.Errorf("%+v", act)
	}
}

func TestNoCandidateAgainstUnconfirmedKeeper(t *testing.T) {
	a := pf("f1", 3000, video(1920, 1080, "h264", 8e6, 1, 0), protected)
	b := pf("f2", 3000, video(1920, 1080, "h264", 8e6, 1, 0), protected)
	c := pf("f3", 1000, video(1280, 720, "h264", 3e6, 1, 0))
	_, d := eval(t, scanOf(model.RelationVisuallySimilar, []model.PhysicalFile{a, b, c},
		[][2]string{{"f1", "f2"}, {"f1", "f3"}, {"f2", "f3"}}), model.PolicyBalanced)
	if d["f3"].Decision != model.DecisionManualReview || !hasReason(d["f3"], "keeper_unconfirmed") {
		t.Errorf("f3 %+v", d["f3"])
	}
}

func TestBalancedRequiresEveryFrameToMatch(t *testing.T) {
	files := []model.PhysicalFile{
		pf("f1", 3000, video(1920, 1080, "h264", 8_000_000, 1, 0)),
		pf("f2", 1000, video(1280, 720, "h264", 2_000_000, 1, 0)),
	}
	r := scanOf(model.RelationVisuallySimilar, files, [][2]string{{"f1", "f2"}})
	r.Edges[0].Visual = &model.VisualMetrics{ComparableFrames: 16, MatchingFrames: 13, MatchRatio: 0.81}
	_, d := eval(t, r, model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionManualReview || !strings.Contains(strings.Join(d["f2"].Reasons, " "), "frames_differ") {
		t.Fatalf("a different ending must not be a candidate: %+v", d["f2"])
	}
}

func TestBalancedRefusesStaticVideo(t *testing.T) {
	files := []model.PhysicalFile{
		pf("f1", 3000, video(1920, 1080, "h264", 8_000_000, 1, 0), still),
		pf("f2", 1000, video(1280, 720, "h264", 2_000_000, 1, 0), still),
	}
	r := scanOf(model.RelationVisuallySimilar, files, [][2]string{{"f1", "f2"}})
	_, d := eval(t, r, model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionManualReview || !strings.Contains(strings.Join(d["f2"].Reasons, " "), "static_video") {
		t.Fatalf("a still picture with possibly different audio must not be a candidate: %+v", d["f2"])
	}
}

func TestNonUTF8PathIsNeverDecided(t *testing.T) {
	files := []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}
	files[1].PathsNotUTF8 = true
	r := scanOf(model.RelationByteIdentical, files, [][2]string{{"f1", "f2"}})
	_, d := eval(t, r, model.PolicyConservative)
	if d["f2"].Decision != model.DecisionInsufficientEvidence {
		t.Fatalf("non-UTF-8 path must need review: %+v", d["f2"])
	}
	for _, m := range d {
		if m.Decision == model.DecisionRedundantCandidate && m.FileID == "f2" {
			t.Fatal("non-UTF-8 file proposed")
		}
	}
}

// Through an overlay or FUSE mount the keeper can be the candidate itself
// under another identity; a low-confidence keeper blocks every candidate.
func TestLowConfidenceKeeperBlocksCandidate(t *testing.T) {
	files := []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}
	files[0].IdentityConfidence = model.ConfidenceLow
	r := scanOf(model.RelationByteIdentical, files, [][2]string{{"f1", "f2"}})
	_, d := eval(t, r, model.PolicyConservative)
	if d["f1"].Decision != model.DecisionRecommendedKeep {
		t.Fatalf("unexpected keeper: %+v", d)
	}
	if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "keeper_identity_confidence_low") {
		t.Fatalf("candidate against a low-confidence keeper: %+v", d["f2"])
	}
}

// A local disk also mounted back over CIFS shows one file twice: a trusted
// local path and a network path. Whichever side is the keeper, the other is
// never proposed, because the server may link them invisibly.
func TestHiddenLinksOnEitherSideBlockCandidate(t *testing.T) {
	for _, side := range []int{0, 1} {
		files := []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}
		files[side].HiddenLinksPossible = true
		r := scanOf(model.RelationByteIdentical, files, [][2]string{{"f1", "f2"}})
		_, d := eval(t, r, model.PolicyConservative)
		for id, m := range d {
			if m.Decision == model.DecisionRedundantCandidate {
				t.Fatalf("network file on side %d: %s proposed: %+v", side, id, m)
			}
		}
		if !hasReason(d["f2"], "hidden_links_possible") {
			t.Fatalf("side %d: reason missing: %+v", side, d["f2"])
		}
	}
}

func TestPlanCarriesSafetyWarnings(t *testing.T) {
	r := scanOf(model.RelationByteIdentical, []model.PhysicalFile{pf("f1", 1), pf("f2", 1)}, [][2]string{{"f1", "f2"}})
	r.Warnings = []model.Warning{
		{Code: "protect_root_unmatched", Path: "/r/Keep", Message: "no scanned file is inside this protected root"},
		{Code: "identity_unconfirmed", Path: "/r/a"},
		{Code: "identity_unconfirmed", Path: "/r/b"},
		{Code: "symlink_broken", Path: "/r/c"},
		{Code: "unrelated_note", Path: "/r/d"},
	}
	ev, _ := eval(t, r, model.PolicyConservative)
	p := BuildPlan(r, ev, "scan.json", model.ToolInfo{})
	all := strings.Join(p.Warnings, "\n")
	if !strings.Contains(all, "protect_root_unmatched: /r/Keep") || !strings.Contains(all, "identity_unconfirmed: 2 occurrence") ||
		!strings.Contains(all, "symlink_broken: 1 occurrence") || strings.Contains(all, "unrelated_note") {
		t.Fatalf("plan warnings: %q", p.Warnings)
	}
}

func TestUnicodeConflictIsNeverDecided(t *testing.T) {
	files := []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}
	files[0].UnicodeConflict, files[1].UnicodeConflict = true, true
	r := scanOf(model.RelationByteIdentical, files, [][2]string{{"f1", "f2"}})
	ev, d := eval(t, r, model.PolicyConservative)
	for id, m := range d {
		if m.Decision != model.DecisionInsufficientEvidence {
			t.Fatalf("%s: %+v", id, m)
		}
	}
	if ev.Groups[0].Space.ReclaimStatus != model.ReclaimUnknown {
		t.Fatalf("reclaim: %+v", ev.Groups[0].Space)
	}
}

func TestBalancedRefusesColourDifferences(t *testing.T) {
	files := []model.PhysicalFile{
		pf("f1", 3000, video(1920, 1080, "h264", 8_000_000, 1, 0), protected),
		pf("f2", 1000, video(1280, 720, "h264", 2_000_000, 1, 0)),
	}
	r := scanOf(model.RelationVisuallySimilar, files, [][2]string{{"f1", "f2"}})
	r.Edges[0].Visual.ColorDelta = 40 // e.g. the only colour copy against a greyscale one
	_, d := eval(t, r, model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "color_differs") {
		t.Fatalf("colour difference must force review: %+v", d["f2"])
	}
	r.Edges[0].Visual.ColorDelta = 0.7 // a plain re-encode
	_, d = eval(t, r, model.PolicyBalanced)
	if d["f2"].Decision != model.DecisionRedundantCandidate {
		t.Fatalf("plain re-encode should still be proposed: %+v", d["f2"])
	}
	files[1].Visual.Params.AlgorithmVersion = 1
	r = scanOf(model.RelationVisuallySimilar, files, [][2]string{{"f1", "f2"}})
	_, d = eval(t, r, model.PolicyBalanced)
	if !hasReason(d["f2"], "rescan_needed") {
		t.Fatalf("old fingerprints without colour must not be proposed: %+v", d["f2"])
	}
}

func TestUnresolvedLinkBlocksCandidate(t *testing.T) {
	files := []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}
	files[1].PossibleLinkRefs = []string{"/r/lib/fav.mp4"}
	r := scanOf(model.RelationByteIdentical, files, [][2]string{{"f1", "f2"}})
	_, d := eval(t, r, model.PolicyConservative)
	if d["f2"].Decision == model.DecisionRedundantCandidate || !hasReason(d["f2"], "unresolved_link") {
		t.Fatalf("file named by an unresolved link was proposed: %+v", d["f2"])
	}
}

// A partial or cancelled scan may have missed links or copies.
func TestIncompleteScanProposesNothing(t *testing.T) {
	for _, st := range []string{model.StatusPartial, model.StatusCancelled} {
		r := scanOf(model.RelationByteIdentical, []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}, [][2]string{{"f1", "f2"}})
		r.Status = st
		_, d := eval(t, r, model.PolicyConservative)
		if d["f2"].Decision == model.DecisionRedundantCandidate || !hasReason(d["f2"], "scan_incomplete") {
			t.Fatalf("%s scan proposed a candidate: %+v", st, d["f2"])
		}
	}
}

// Without a protected keeper nothing is proposed: names cannot tell a
// library from a bin, snapshot or backup, so the user declares the copy
// that stays.
func TestCandidateNeedsProtectedKeeper(t *testing.T) {
	r := scanOf(model.RelationByteIdentical, []model.PhysicalFile{pf("f1", 1000), pf("f2", 1000)}, [][2]string{{"f1", "f2"}})
	ev, d := eval(t, r, model.PolicyConservative)
	if d["f2"].Decision != model.DecisionManualReview || !hasReason(d["f2"], "no_protected_keeper") {
		t.Fatalf("unprotected keeper allowed a candidate: %+v", d["f2"])
	}
	if ev.Groups[0].Action != model.ActionReview || ev.Groups[0].Space.ReclaimStatus != model.ReclaimUnknown {
		t.Fatalf("group: %+v", ev.Groups[0])
	}
	r = scanOf(model.RelationByteIdentical, []model.PhysicalFile{pf("f1", 1000, protected), pf("f2", 1000)}, [][2]string{{"f1", "f2"}})
	_, d = eval(t, r, model.PolicyConservative)
	if d["f2"].Decision != model.DecisionRedundantCandidate {
		t.Fatalf("protected keeper: %+v", d["f2"])
	}
}

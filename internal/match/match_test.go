package match

import (
	"math/rand"
	"testing"

	"github.com/hidetzu/reelwarden/internal/fingerprint"
	"github.com/hidetzu/reelwarden/internal/model"
)

const n = 16

func seq(seed int64) []uint64 {
	r := rand.New(rand.NewSource(seed))
	out := make([]uint64, n)
	for i := range out {
		out[i] = r.Uint64()
	}
	return out
}

// flip changes k bits of each hash deterministically.
func flip(hs []uint64, k int) []uint64 {
	out := append([]uint64(nil), hs...)
	for i := range out {
		for b := 0; b < k; b++ {
			out[i] ^= 1 << uint((i*7+b*5)%64)
		}
	}
	return out
}

func file(id string, dur float64, hashes []uint64, lowInfo ...int) model.PhysicalFile {
	p := fingerprint.DefaultVisualParams()
	v := &model.VisualFingerprint{Params: p}
	low := map[int]bool{}
	for _, i := range lowInfo {
		low[i] = true
	}
	for i, h := range hashes {
		v.Frames = append(v.Frames, model.FrameSample{Index: i, DHash: h, LowInfo: low[i]})
		if low[i] {
			v.LowInfoCount++
		}
	}
	return model.PhysicalFile{
		ID: id, IdentityStatus: model.IdentityKnown, Size: 100,
		Media:  &model.MediaInfo{DurationSec: dur, DurationKnown: true},
		Visual: v,
	}
}

func edgesBetween(r Result, a, b string) []model.MatchEdge {
	var out []model.MatchEdge
	for _, e := range r.Edges {
		if (e.Left == a && e.Right == b) || (e.Left == b && e.Right == a) {
			out = append(out, e)
		}
	}
	return out
}

func TestReencodeIsVisuallySimilar(t *testing.T) {
	base := seq(1)
	files := []model.PhysicalFile{file("f1", 60, base), file("f2", 60.04, flip(base, 4))}
	r := Build(files, DefaultParams(), true)
	es := edgesBetween(r, "f1", "f2")
	if len(es) != 1 || es[0].Relation != model.RelationVisuallySimilar {
		t.Fatalf("edges %+v", r.Edges)
	}
	if len(r.Groups) != 1 || r.Groups[0].Relation != model.RelationVisuallySimilar {
		t.Errorf("groups %+v", r.Groups)
	}
}

func TestDifferentContentNoEdge(t *testing.T) {
	files := []model.PhysicalFile{file("f1", 60, seq(1)), file("f2", 60, seq(2))}
	r := Build(files, DefaultParams(), true)
	if len(r.Edges) != 0 || len(r.Groups) != 0 {
		t.Errorf("unexpected %+v", r)
	}
}

func TestSharedIntroIsNotSimilar(t *testing.T) {
	a := seq(1)
	b := seq(2)
	copy(b[:3], a[:3]) // same first 3 samples (intro)
	files := []model.PhysicalFile{file("f1", 60, a), file("f2", 60, b)}
	r := Build(files, DefaultParams(), true)
	for _, e := range r.Edges {
		if e.Relation == model.RelationVisuallySimilar {
			t.Errorf("shared intro must not be visually_similar: %+v", e)
		}
	}
	if len(r.Groups) != 0 {
		t.Errorf("no group expected")
	}
}

func TestHalfSharedIsUncertainAndUngrouped(t *testing.T) {
	a := seq(1)
	b := seq(2)
	copy(b[:10], a[:10])
	r := Build([]model.PhysicalFile{file("f1", 60, a), file("f2", 60, b)}, DefaultParams(), true)
	es := edgesBetween(r, "f1", "f2")
	if len(es) != 1 || es[0].Relation != model.RelationUncertain {
		t.Fatalf("want uncertain, got %+v", r.Edges)
	}
	if len(r.Groups) != 0 {
		t.Errorf("uncertain edges must not form groups: %+v", r.Groups)
	}
}

func TestMostlyBlackIsNotSimilar(t *testing.T) {
	a := seq(1)
	b := seq(2)
	// Both have only 3 informative frames, and they happen to match.
	copy(b[13:], a[13:])
	low := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	r := Build([]model.PhysicalFile{file("f1", 60, a, low...), file("f2", 60, b, low...)}, DefaultParams(), true)
	for _, e := range r.Edges {
		if e.Relation == model.RelationVisuallySimilar {
			t.Errorf("too few informative frames must not be similar: %+v", e)
		}
	}
}

func TestDurationWindowExcludesDistantPairs(t *testing.T) {
	base := seq(1)
	r := Build([]model.PhysicalFile{file("f1", 60, base), file("f2", 75, base)}, DefaultParams(), true)
	if len(r.Edges) != 0 {
		t.Errorf("durations 60 vs 75 must not be compared: %+v", r.Edges)
	}
}

// A≈B, B≈C, A≉C: one group, but no direct A–C edge.
func TestChainDoesNotCreateDirectEdge(t *testing.T) {
	b := seq(1)
	a := append([]uint64(nil), b...)
	c := append([]uint64(nil), b...)
	// Each of A and C is 8 bits from B on every frame, but 16 bits from each other.
	for i := range b {
		a[i] = b[i] ^ 0x00000000000000FF
		c[i] = b[i] ^ 0xFF00000000000000
	}
	r := Build([]model.PhysicalFile{file("A", 60, a), file("B", 60, b), file("C", 60, c)}, DefaultParams(), true)
	if es := edgesBetween(r, "A", "B"); len(es) != 1 || es[0].Relation != model.RelationVisuallySimilar {
		t.Fatalf("A-B: %+v", es)
	}
	if es := edgesBetween(r, "B", "C"); len(es) != 1 || es[0].Relation != model.RelationVisuallySimilar {
		t.Fatalf("B-C: %+v", es)
	}
	for _, e := range edgesBetween(r, "A", "C") {
		if e.Relation == model.RelationVisuallySimilar {
			t.Fatalf("A-C must not be visually similar: %+v", e)
		}
	}
	if len(r.Groups) != 1 || len(r.Groups[0].Members) != 3 {
		t.Fatalf("groups %+v", r.Groups)
	}
}

func TestExactEdgesRequireFullHashAndSkipChanged(t *testing.T) {
	mk := func(id, sha, partial string, changed bool) model.PhysicalFile {
		return model.PhysicalFile{ID: id, IdentityStatus: model.IdentityKnown, Size: 10, ChangedDuringScan: changed,
			Exact: &model.ExactFingerprint{SHA256: sha, PartialSHA256: partial}}
	}
	files := []model.PhysicalFile{
		mk("f1", "aaaaaaaaaaaaaaaaaaaa", "p", false),
		mk("f2", "aaaaaaaaaaaaaaaaaaaa", "p", false),
		mk("f3", "", "p", false), // partial only: never identical
		mk("f4", "aaaaaaaaaaaaaaaaaaaa", "p", true),
		mk("f5", "bbbbbbbbbbbbbbbbbbbb", "p", false), // same size and partial, different full
	}
	r := Build(files, DefaultParams(), false)
	if len(r.Edges) != 1 || r.Edges[0].Relation != model.RelationByteIdentical {
		t.Fatalf("edges %+v", r.Edges)
	}
	if len(r.Groups) != 1 || r.Groups[0].Relation != model.RelationByteIdentical {
		t.Errorf("groups %+v", r.Groups)
	}
}

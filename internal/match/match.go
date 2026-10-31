// Package match turns fingerprints into evidence: byte_identical edges from
// full SHA-256 equality, visually_similar / uncertain edges from validated
// frame comparisons, and groups that never infer a relation they did not
// observe directly (docs/design.md §7).
package match

import (
	"fmt"
	"math"
	"sort"

	"github.com/hidetzu/reelwarden/internal/fingerprint"
	"github.com/hidetzu/reelwarden/internal/model"
)

// DefaultParams are the thresholds recorded in docs/design.md §7.
func DefaultParams() model.MatchParams {
	return model.MatchParams{
		DurationToleranceSeconds: 2,
		DurationToleranceRatio:   0.02,
		FrameHammingThreshold:    10,
		MinComparableFrames:      8,
		SimilarMatchRatio:        0.80,
		UncertainMatchRatio:      0.50,
		MaxMeanHamming:           12,
		// Re-encodes of the synthetic set stay below 1.3; colour grading,
		// hue shifts (12 degrees and up) and greyscale are above 6.
		MaxColorDelta: 3,
	}
}

// DurationTolerance returns the allowed duration difference for d.
func DurationTolerance(p model.MatchParams, d float64) float64 {
	return math.Max(p.DurationToleranceSeconds, p.DurationToleranceRatio*d)
}

type edgeBuilder struct {
	edges []model.MatchEdge
	seq   int
}

func (b *edgeBuilder) add(e model.MatchEdge) {
	b.seq++
	e.ID = fmt.Sprintf("m%06d", b.seq)
	if e.Left > e.Right {
		e.Left, e.Right = e.Right, e.Left
	}
	b.edges = append(b.edges, e)
}

// Result holds the produced edges and groups.
type Result struct {
	Edges  []model.MatchEdge
	Groups []model.DuplicateGroup
}

// Build compares the physical files and groups them. files must already
// carry Exact / Visual / Media fingerprints where available.
func Build(files []model.PhysicalFile, p model.MatchParams, visual bool) Result {
	var b edgeBuilder
	sets := HashSets(files)
	buildExact(&b, files, sets)
	if visual {
		buildVisual(&b, files, p, VisualRepresentatives(files, sets))
	}
	return Result{Edges: b.edges, Groups: group(files, b.edges)}
}

// HashSets returns, for every full SHA-256 shared by two or more files that
// did not change during the scan, the indexes of those files sorted by ID.
// Equal SHA-256 is an equivalence relation, so a set needs no pairwise
// evidence: every member is byte-identical to every other.
func HashSets(files []model.PhysicalFile) map[string][]int {
	byHash := map[string][]int{}
	for i := range files {
		f := &files[i]
		if f.Exact == nil || f.Exact.SHA256 == "" || f.ChangedDuringScan {
			continue
		}
		byHash[f.Exact.SHA256] = append(byHash[f.Exact.SHA256], i)
	}
	for h, idx := range byHash {
		if len(idx) < 2 {
			delete(byHash, h)
			continue
		}
		sort.Slice(idx, func(a, b int) bool { return files[idx[a]].ID < files[idx[b]].ID })
	}
	return byHash
}

// buildExact links every member of a byte-identical set to the set's first
// member (by ID): n-1 edges instead of n(n-1)/2, with no evidence lost,
// since each edge states the full SHA-256 the whole set shares.
func buildExact(b *edgeBuilder, files []model.PhysicalFile, sets map[string][]int) {
	hashes := make([]string, 0, len(sets))
	for h := range sets {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for _, h := range hashes {
		idx := sets[h]
		head := &files[idx[0]]
		for _, i := range idx[1:] {
			f := &files[i]
			ev := []string{
				fmt.Sprintf("full SHA-256 equal (%s…)", h[:16]),
				fmt.Sprintf("size equal (%d bytes)", f.Size),
			}
			if len(idx) > 2 {
				ev = append(ev, fmt.Sprintf("one of %d byte-identical files with this SHA-256; each is linked to %s", len(idx), head.ID))
			}
			if f.IdentityStatus == model.IdentityKnown && head.IdentityStatus == model.IdentityKnown {
				ev = append(ev, "different physical files (identity differs)")
			} else {
				ev = append(ev, "file identity not confirmed: these may be the same physical file reached by different paths")
			}
			b.add(model.MatchEdge{Left: head.ID, Right: f.ID, Relation: model.RelationByteIdentical, Confidence: model.ConfidenceHigh, Evidence: ev})
		}
	}
}

// VisualRepresentatives maps every member of a byte-identical set to the one
// member that takes part in visual comparison (the first by ID that has a
// visual fingerprint and a known duration). Byte-identical files have the
// same picture, so comparing one of them stands for all, and visual work
// stays linear in the number of copies.
func VisualRepresentatives(files []model.PhysicalFile, sets map[string][]int) map[string]string {
	rep := map[string]string{}
	for _, idx := range sets {
		r := ""
		for _, i := range idx {
			f := &files[i]
			if f.Visual != nil && f.Media != nil && f.Media.DurationKnown {
				r = f.ID
				break
			}
		}
		if r == "" {
			continue
		}
		for _, i := range idx {
			rep[files[i].ID] = r
		}
	}
	return rep
}

type vcand struct {
	idx int
	dur float64
}

func buildVisual(b *edgeBuilder, files []model.PhysicalFile, p model.MatchParams, rep map[string]string) {
	var cs []vcand
	for i := range files {
		f := &files[i]
		if f.Visual == nil || f.Media == nil || !f.Media.DurationKnown || f.ChangedDuringScan {
			continue
		}
		if r, ok := rep[f.ID]; ok && r != f.ID {
			continue // a byte-identical copy of r: r stands for it
		}
		cs = append(cs, vcand{idx: i, dur: f.Media.DurationSec})
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].dur != cs[j].dur {
			return cs[i].dur < cs[j].dur
		}
		return files[cs[i].idx].ID < files[cs[j].idx].ID
	})
	for i := range cs {
		for j := i + 1; j < len(cs); j++ {
			// Window: stop once the duration gap exceeds tolerance for the longer one.
			if cs[j].dur-cs[i].dur > DurationTolerance(p, cs[j].dur) {
				break
			}
			l, r := &files[cs[i].idx], &files[cs[j].idx]
			if l.Exact != nil && r.Exact != nil && l.Exact.SHA256 != "" && l.Exact.SHA256 == r.Exact.SHA256 {
				continue
			}
			if e, ok := Compare(l, r, p); ok {
				b.add(e)
			}
		}
	}
}

// Compare validates one pair of fingerprinted files. It returns ok=false
// when there is no relation worth reporting.
func Compare(l, r *model.PhysicalFile, p model.MatchParams) (model.MatchEdge, bool) {
	lv, rv := l.Visual, r.Visual
	if lv == nil || rv == nil || len(lv.Frames) != len(rv.Frames) || len(lv.Frames) == 0 {
		return model.MatchEdge{}, false
	}
	if fingerprint.ParamsKey(lv.Params) != fingerprint.ParamsKey(rv.Params) {
		return model.MatchEdge{}, false
	}
	m := model.VisualMetrics{
		LeftLowInfoRatio:     ratio(lv.LowInfoCount, len(lv.Frames)),
		RightLowInfoRatio:    ratio(rv.LowInfoCount, len(rv.Frames)),
		DurationDeltaSeconds: round3(math.Abs(l.Media.DurationSec - r.Media.DurationSec)),
	}
	total := 0
	var color float64
	for i := range lv.Frames {
		a, c := lv.Frames[i], rv.Frames[i]
		if a.Failed || c.Failed || a.LowInfo || c.LowInfo {
			continue
		}
		m.ComparableFrames++
		color += colorDistance(a, c)
		d := fingerprint.Hamming(a.DHash, c.DHash)
		total += d
		if d <= p.FrameHammingThreshold {
			m.MatchingFrames++
		}
	}
	if m.ComparableFrames == 0 {
		return model.MatchEdge{}, false
	}
	m.MatchRatio = round3(ratio(m.MatchingFrames, m.ComparableFrames))
	m.MeanHamming = round3(float64(total) / float64(m.ComparableFrames))
	m.ColorDelta = round3(color / float64(m.ComparableFrames))
	e := model.MatchEdge{Left: l.ID, Right: r.ID, Visual: &m}
	ev := []string{
		fmt.Sprintf("visual fingerprint: %d of %d informative samples match (mean Hamming distance %.1f of 64 bits)", m.MatchingFrames, m.ComparableFrames, m.MeanHamming),
		fmt.Sprintf("duration difference %.3fs", m.DurationDeltaSeconds),
	}
	if lv.LowInfoCount+rv.LowInfoCount > 0 {
		ev = append(ev, fmt.Sprintf("low-information samples excluded: %d / %d", lv.LowInfoCount, rv.LowInfoCount))
	}
	if p.MaxColorDelta > 0 && m.ColorDelta > p.MaxColorDelta {
		ev = append(ev, fmt.Sprintf("colours differ (mean colour distance %.1f): greyscale, tinted or colour-graded", m.ColorDelta))
	}
	ev = append(ev, "not byte-identical")
	switch {
	case m.ComparableFrames >= p.MinComparableFrames && m.MatchRatio >= p.SimilarMatchRatio && m.MeanHamming <= p.MaxMeanHamming:
		e.Relation = model.RelationVisuallySimilar
		e.Confidence = model.ConfidenceHigh
		if m.ComparableFrames < p.MinComparableFrames+4 || m.MatchRatio < 0.9 {
			e.Confidence = "medium"
		}
	case m.ComparableFrames >= p.MinComparableFrames/2 && m.MatchRatio >= p.UncertainMatchRatio:
		e.Relation = model.RelationUncertain
		e.Confidence = model.ConfidenceLow
		if m.ComparableFrames < p.MinComparableFrames {
			ev = append(ev, fmt.Sprintf("too few informative samples (%d < %d) to conclude", m.ComparableFrames, p.MinComparableFrames))
		} else {
			ev = append(ev, "partial agreement only: possibly shared segments (intro, recap) or heavy edits")
		}
	default:
		return model.MatchEdge{}, false
	}
	e.Evidence = ev
	return e, true
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// group forms connected components over byte_identical and
// visually_similar edges. Uncertain edges never join groups.
func group(files []model.PhysicalFile, edges []model.MatchEdge) []model.DuplicateGroup {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}
	for _, f := range files {
		parent[f.ID] = f.ID
	}
	for _, e := range edges {
		if e.Relation == model.RelationByteIdentical || e.Relation == model.RelationVisuallySimilar {
			union(e.Left, e.Right)
		}
	}
	members := map[string][]string{}
	for _, f := range files {
		members[find(f.ID)] = append(members[find(f.ID)], f.ID)
	}
	var roots []string
	for r, m := range members {
		if len(m) > 1 {
			roots = append(roots, r)
		}
	}
	sort.Strings(roots)
	// Edges per group, collected in one pass (not one pass per group).
	byRoot := map[string][]*model.MatchEdge{}
	for i := range edges {
		e := &edges[i]
		if e.Relation == model.RelationByteIdentical || e.Relation == model.RelationVisuallySimilar {
			r := find(e.Left)
			byRoot[r] = append(byRoot[r], e)
		}
	}
	groups := make([]model.DuplicateGroup, 0, len(roots))
	for i, r := range roots {
		g := model.DuplicateGroup{ID: fmt.Sprintf("g%04d", i+1), Members: members[r]}
		sort.Strings(g.Members)
		rels := map[string]bool{}
		for _, e := range byRoot[r] {
			g.Edges = append(g.Edges, e.ID)
			rels[e.Relation] = true
		}
		switch {
		case len(rels) > 1:
			g.Relation = model.RelationMixed
		case rels[model.RelationByteIdentical]:
			g.Relation = model.RelationByteIdentical
		default:
			g.Relation = model.RelationVisuallySimilar
		}
		groups = append(groups, g)
	}
	return groups
}

// colorDistance compares two frames' colour: the mean per-cell Cb/Cr
// distance when both have cells (else the whole-frame one), plus the
// difference in chroma magnitude.
func colorDistance(a, b model.FrameSample) float64 {
	d := math.Hypot(a.Cb-b.Cb, a.Cr-b.Cr)
	if n := len(a.CellCbCr); n > 0 && n == len(b.CellCbCr) {
		var sum float64
		for i := 0; i+1 < n; i += 2 {
			sum += math.Hypot(a.CellCbCr[i]-b.CellCbCr[i], a.CellCbCr[i+1]-b.CellCbCr[i+1])
		}
		d = sum / float64(n/2)
	}
	return d + math.Abs(a.Chroma-b.Chroma)
}

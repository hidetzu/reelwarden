// Package decision turns groups and edges into explained recommendations
// and read-only plans (docs/design.md §9, §10). Nothing here touches files.
package decision

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hidetzu/reelwarden/internal/fingerprint"
	"github.com/hidetzu/reelwarden/internal/match"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/quality"
)

// ReclaimNote explains why real savings may differ from the estimate.
const ReclaimNote = "Estimate only. Reflinks, filesystem compression, snapshots and NAS deduplication can make the real freed space differ."

// Evaluate makes per-member decisions for every group in res.
func Evaluate(res *model.ScanResult, policy string) (*model.Evaluation, error) {
	if policy == "" {
		policy = model.PolicyConservative
	}
	if policy != model.PolicyConservative && policy != model.PolicyBalanced {
		return nil, fmt.Errorf("unknown policy %q (use conservative or balanced)", policy)
	}
	ix := model.NewIndex(res)
	vrep := match.VisualRepresentatives(res.Files, match.HashSets(res.Files))
	mp := match.DefaultParams()
	if res.Params.Match != nil {
		mp = *res.Params.Match
	}
	ev := &model.Evaluation{Policy: policy, Groups: []model.GroupEvaluation{}}
	for gi := range res.Groups {
		ge := evaluateGroup(ix, vrep, &res.Groups[gi], policy, mp, res.Status != model.StatusComplete)
		ev.Groups = append(ev.Groups, ge)
		s := &ev.Summary
		s.Groups++
		for _, m := range ge.Members {
			switch m.Decision {
			case model.DecisionRecommendedKeep:
				s.RecommendedKeep++
			case model.DecisionRedundantCandidate:
				s.RedundantCandidates++
			case model.DecisionManualReview:
				s.ManualReview++
			case model.DecisionInsufficientEvidence:
				s.InsufficientEvidence++
			}
		}
		s.PotentialReclaimBytes += ge.Space.PotentialReclaimBytes
		if ge.Space.ReclaimStatus == model.ReclaimUnknown {
			s.UnknownReclaimGroups++
		}
	}
	return ev, nil
}

type member struct {
	f       *model.PhysicalFile
	prof    quality.Profile
	dec     string
	reasons []string
	edge    string
}

func (m *member) set(dec string, reasons ...string) {
	m.dec = dec
	m.reasons = append(m.reasons, reasons...)
}

// incomplete is set for partial or cancelled scans: some links or files may
// not have been seen, so no member is proposed.
func evaluateGroup(ix *model.Index, vrep map[string]string, g *model.DuplicateGroup, policy string, mp model.MatchParams, incomplete bool) model.GroupEvaluation {
	ge := model.GroupEvaluation{GroupID: g.ID, Relation: g.Relation}
	ms := make([]*member, 0, len(g.Members))
	for _, id := range g.Members {
		f := ix.Files[id]
		ms = append(ms, &member{f: f, prof: quality.ProfileOf(f)})
	}
	allExact := g.Relation == model.RelationByteIdentical

	// Rule 1: insufficient evidence (only matters when quality must be judged).
	var eligible []*member
	for _, m := range ms {
		if !allExact && (m.f.Media == nil || m.f.Media.ProbeError != "") {
			m.set(model.DecisionInsufficientEvidence, "media information unavailable; quality cannot be compared")
			continue
		}
		if m.f.ChangedDuringScan {
			m.set(model.DecisionInsufficientEvidence, "file changed during scan")
			continue
		}
		if m.f.UnicodeConflict {
			m.set(model.DecisionInsufficientEvidence, "a path differs from another only in Unicode normalization (NFC/NFD); it cannot be shown unambiguously and may be the same file")
			continue
		}
		if m.f.PathsNotUTF8 {
			m.set(model.DecisionInsufficientEvidence, "a path is not valid UTF-8 and cannot be shown unambiguously; review by hand")
			continue
		}
		eligible = append(eligible, m)
	}
	if len(eligible) == 0 {
		return finish(ge, ms, nil, ix)
	}

	// Choose the keeper candidate.
	sort.SliceStable(eligible, func(i, j int) bool { return keeperLess(eligible[i], eligible[j], allExact) })
	keeper := eligible[0]
	keeper.set(model.DecisionRecommendedKeep, keeperReasons(keeper, eligible, allExact)...)

	protectedCount := 0
	for _, m := range eligible {
		if m.f.Protected {
			protectedCount++
		}
	}
	if protectedCount > 1 {
		for _, m := range eligible {
			if m.f.Protected {
				m.dec = model.DecisionManualReview
				m.reasons = []string{fmt.Sprintf("multiple members are under protected roots (%d); choose manually", protectedCount)}
			}
		}
		ge.ReviewReasons = append(ge.ReviewReasons, "multiple_protected_members")
	}

	for _, m := range eligible[1:] {
		if m.dec != "" {
			continue
		}
		decideAgainstKeeper(ix, vrep, keeper, m, policy, mp, incomplete, &ge)
	}
	// If any member could not be ranked against the keeper because of a
	// blocking difference, the keeper itself is not a safe recommendation.
	if keeper.dec == model.DecisionRecommendedKeep {
		for _, m := range eligible[1:] {
			if hasPrefixReason(m.reasons, "blocking:") || hasPrefixReason(m.reasons, "other member may be better") {
				keeper.dec = model.DecisionManualReview
				keeper.reasons = append(keeper.reasons, "a member differs in ways that prevent an automatic preference; review the group")
				break
			}
		}
	}
	// Never propose a candidate against a keeper that is itself unconfirmed.
	if keeper.dec != model.DecisionRecommendedKeep {
		for _, m := range eligible[1:] {
			if m.dec == model.DecisionRedundantCandidate {
				m.dec = model.DecisionManualReview
				m.reasons = append(m.reasons, "keeper_unconfirmed: the keeper candidate itself needs review, so no member is proposed as redundant")
				ge.ReviewReasons = appendUnique(ge.ReviewReasons, "keeper_unconfirmed")
			}
		}
	}
	return finish(ge, ms, keeper, ix)
}

// evidenceBetween returns the edge that relates keeper k and member m, and a
// note when it is not a direct edge between them. Byte-identical sets are
// stored as stars (each copy linked to the first), and visual comparison is
// done once per set, so evidence may come through a byte-identical copy.
// That is exact: a copy has the same bytes, hence the same picture. A
// chain of visual similarities is never accepted (no_direct_evidence).
func evidenceBetween(ix *model.Index, vrep map[string]string, k, m *model.PhysicalFile) (*model.MatchEdge, string) {
	if e := ix.EdgeBetween(k.ID, m.ID); e != nil {
		return e, ""
	}
	if k.Exact != nil && m.Exact != nil && k.Exact.SHA256 != "" && k.Exact.SHA256 == m.Exact.SHA256 &&
		!k.ChangedDuringScan && !m.ChangedDuringScan {
		for _, e := range ix.EdgesByFile[m.ID] {
			if e.Relation == model.RelationByteIdentical {
				return e, "same full SHA-256 as the keeper (one byte-identical set)"
			}
		}
	}
	rk, rm := k.ID, m.ID
	if r, ok := vrep[rk]; ok {
		rk = r
	}
	if r, ok := vrep[rm]; ok {
		rm = r
	}
	if rk != k.ID || rm != m.ID {
		if e := ix.EdgeBetween(rk, rm); e != nil {
			return e, "compared through a byte-identical copy (" + rk + " ~ " + rm + ")"
		}
	}
	return nil, ""
}

func hasPrefixReason(rs []string, p string) bool {
	for _, r := range rs {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}

// keeperLess orders members by keeper preference.
func keeperLess(a, b *member, exact bool) bool {
	if a.f.InProtectedLibrary != b.f.InProtectedLibrary {
		return a.f.InProtectedLibrary
	}
	if a.f.Protected != b.f.Protected {
		return a.f.Protected
	}
	if !exact {
		if a.prof.Pixels != b.prof.Pixels {
			return a.prof.Pixels > b.prof.Pixels
		}
		// Only a meaningful bitrate difference counts; container-level
		// rounding must not outrank reference counts.
		if a.prof.Codec == b.prof.Codec && a.prof.VideoBitRate > 0 && b.prof.VideoBitRate > 0 {
			ab, bb := float64(a.prof.VideoBitRate), float64(b.prof.VideoBitRate)
			if ab >= quality.BitRateRatio*bb {
				return true
			}
			if bb >= quality.BitRateRatio*ab {
				return false
			}
		}
	}
	ar, br := len(a.f.KnownPaths)+len(a.f.SymlinkRefs), len(b.f.KnownPaths)+len(b.f.SymlinkRefs)
	if ar != br {
		return ar > br
	}
	if !a.f.MTime.Equal(b.f.MTime) {
		return a.f.MTime.Before(b.f.MTime)
	}
	if len(a.f.PrimaryPath()) != len(b.f.PrimaryPath()) {
		return len(a.f.PrimaryPath()) < len(b.f.PrimaryPath())
	}
	return a.f.ID < b.f.ID
}

func keeperReasons(k *member, all []*member, exact bool) []string {
	var r []string
	if k.f.Protected {
		r = append(r, "under protected root "+k.f.ProtectedByRoot)
	}
	if exact {
		r = append(r, "byte-identical copies have equal quality; preferred by protection, reference count, age and path length")
	} else {
		r = append(r, "best ranked by protection, then resolution, then same-codec bitrate")
	}
	if n := len(k.f.KnownPaths) + len(k.f.SymlinkRefs); n > 1 {
		r = append(r, fmt.Sprintf("referenced by %d known paths", n))
	}
	return r
}

// decideAgainstKeeper decides m against keeper k with the scan's match
// parameters.
func decideAgainstKeeper(ix *model.Index, vrep map[string]string, k, m *member, policy string, mp model.MatchParams, incomplete bool, ge *model.GroupEvaluation) {
	e, via := evidenceBetween(ix, vrep, k.f, m.f)
	if via != "" {
		m.reasons = append(m.reasons, via)
	}
	if e == nil {
		m.set(model.DecisionManualReview, "no_direct_evidence: this file was grouped through another member and was never matched directly against the keeper")
		ge.ReviewReasons = appendUnique(ge.ReviewReasons, "no_direct_evidence")
		return
	}
	m.edge = e.ID
	if m.f.Protected {
		m.set(model.DecisionManualReview, "under protected root "+m.f.ProtectedByRoot+"; never proposed as redundant")
		ge.ReviewReasons = appendUnique(ge.ReviewReasons, "protected_member")
		return
	}
	switch e.Relation {
	case model.RelationByteIdentical:
		m.reasons = append(m.reasons, "byte-identical to the keeper (full SHA-256)")
	case model.RelationVisuallySimilar:
		if m.f.Visual == nil || k.f.Visual == nil {
			m.set(model.DecisionInsufficientEvidence, "visual fingerprint missing")
			return
		}
		diffs := quality.BlockingDifferences(k.prof, m.prof)
		if len(diffs) > 0 {
			rs := make([]string, 0, len(diffs))
			for _, d := range diffs {
				rs = append(rs, "blocking: "+d.String())
				ge.ReviewReasons = appendUnique(ge.ReviewReasons, d.Code)
			}
			m.set(model.DecisionManualReview, rs...)
			return
		}
		c := quality.Compare(k.prof, m.prof)
		switch c.Verdict {
		case quality.LeftBetter:
			m.reasons = append(m.reasons, "keeper is better: "+strings.Join(c.Reasons, "; "))
		case quality.RightBetter:
			m.set(model.DecisionManualReview, "other member may be better than the protected/preferred keeper: "+strings.Join(c.Reasons, "; "))
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "keeper_not_best")
			return
		default:
			m.set(model.DecisionManualReview, c.Code+": "+strings.Join(c.Reasons, "; "))
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, c.Code)
			return
		}
		if policy == model.PolicyConservative {
			m.set(model.DecisionManualReview, "policy_conservative_visual: visually similar files are never proposed as redundant under the conservative policy")
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "policy_conservative_visual")
			return
		}
		// balanced: only sampled frames are compared, so require every one of
		// them to agree and refuse near-static videos, where the picture says
		// little and audio (never compared) carries the content.
		if v := e.Visual; v == nil || v.MatchingFrames < v.ComparableFrames {
			n, t := 0, 0
			if v != nil {
				n, t = v.ComparableFrames-v.MatchingFrames, v.ComparableFrames
			}
			m.set(model.DecisionManualReview, fmt.Sprintf("frames_differ: %d of %d sampled frames differ; scenes, endings or overlays may differ", n, t))
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "frames_differ")
			return
		}
		if k.f.Visual.Params.AlgorithmVersion < 3 || m.f.Visual.Params.AlgorithmVersion < 3 {
			m.set(model.DecisionManualReview, "rescan_needed: fingerprints from an older version carry no colour information")
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "rescan_needed")
			return
		}
		if limit := mp.MaxColorDelta; limit <= 0 || e.Visual.ColorDelta > limit {
			m.set(model.DecisionManualReview, fmt.Sprintf("color_differs: mean colour distance %.1f; a greyscale, tinted or colour-graded copy loses information", e.Visual.ColorDelta))
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "color_differs")
			return
		}
		if isStatic(k.f.Visual, mp.FrameHammingThreshold) || isStatic(m.f.Visual, mp.FrameHammingThreshold) {
			m.set(model.DecisionManualReview, "static_video: sampled frames barely change; audio is not compared, so the recordings may differ")
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, "static_video")
			return
		}
	default:
		m.set(model.DecisionManualReview, "relation "+e.Relation+" does not support a decision")
		return
	}
	// Link and identity safety checks before proposing a candidate.
	var block []string
	if m.f.UnverifiedExternalLinks {
		if m.f.NlinkKnown && m.f.Nlink > uint64(len(m.f.KnownPaths)) {
			block = append(block, fmt.Sprintf("unverified_external_links: nlink=%d but only %d paths were found in the scanned roots", m.f.Nlink, len(m.f.KnownPaths)))
		} else {
			block = append(block, "unverified_external_links: link count cannot be trusted on this filesystem")
		}
	}
	if m.f.IdentityConfidence != model.ConfidenceHigh {
		block = append(block, "identity_confidence_"+m.f.IdentityConfidence+": file identity may be unreliable (network or unknown filesystem)")
	}
	if k.f.IdentityConfidence != model.ConfidenceHigh {
		// Through an overlay, FUSE or network mount the keeper may be this very
		// file under another identity; removing it would remove the keeper.
		block = append(block, "keeper_identity_confidence_"+k.f.IdentityConfidence+": the keeper's identity may be unreliable, so it may be this same file")
	}
	if len(m.f.PossibleLinkRefs) > 0 {
		block = append(block, fmt.Sprintf("unresolved_link: %d link(s) that cannot be resolved here name this file (e.g. %s); they may refer to it", len(m.f.PossibleLinkRefs), m.f.PossibleLinkRefs[0]))
	}
	if len(m.f.SymlinkRefs) > 0 {
		block = append(block, fmt.Sprintf("referenced_by_symlinks: %d symlinks point to this file and would break", len(m.f.SymlinkRefs)))
	}
	if m.f.HiddenLinksPossible || k.f.HiddenLinksPossible {
		block = append(block, "hidden_links_possible: on a network filesystem the server can resolve symlinks the client cannot see, so these paths may be one file")
	}
	switch {
	case m.f.IdentityStatus == model.IdentityUnconfirmed || k.f.IdentityStatus == model.IdentityUnconfirmed:
		block = append(block, "identity_unconfirmed: the filesystem cannot confirm whether these paths are one file or two; removing one may remove the keeper")
	case m.f.IdentityStatus != model.IdentityKnown || k.f.IdentityStatus != model.IdentityKnown:
		block = append(block, "identity_unknown: the two paths may be the same physical file")
	}
	if len(block) > 0 {
		m.set(model.DecisionManualReview, block...)
		for _, b := range block {
			code, _, _ := strings.Cut(b, ":")
			ge.ReviewReasons = appendUnique(ge.ReviewReasons, code)
		}
		return
	}
	if incomplete {
		m.set(model.DecisionManualReview, "scan_incomplete: the scan did not finish (partial or cancelled), so links or copies may have been missed; rescan before deciding")
		ge.ReviewReasons = appendUnique(ge.ReviewReasons, "scan_incomplete")
		return
	}
	// The copy that stays must be one the user declared trustworthy. Names
	// cannot tell a library from a recycle bin, snapshot, backup or version
	// store in every case, so reelwarden never guesses which copy is safe.
	if !k.f.InProtectedLibrary {
		m.set(model.DecisionManualReview, "no_protected_keeper: no copy in this group is under a --protect-root; protect the folder that should keep it to get candidates")
		ge.ReviewReasons = appendUnique(ge.ReviewReasons, "no_protected_keeper")
		return
	}
	m.set(model.DecisionRedundantCandidate, "candidate only: not a deletion approval")
}

// isStatic reports whether all informative frames of v lie within thr bits
// of each other, i.e. the picture barely changes over the whole video.
func isStatic(v *model.VisualFingerprint, thr int) bool {
	var hs []uint64
	for _, f := range v.Frames {
		if !f.LowInfo && !f.Failed {
			hs = append(hs, f.DHash)
		}
	}
	for i := range hs {
		for j := i + 1; j < len(hs); j++ {
			if fingerprint.Hamming(hs[i], hs[j]) > thr {
				return false
			}
		}
	}
	return true
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func finish(ge model.GroupEvaluation, ms []*member, keeper *member, ix *model.Index) model.GroupEvaluation {
	if keeper != nil {
		ge.Keeper = keeper.f.ID
	}
	undecided := false
	candidates := 0
	edgeSeen := map[string]bool{}
	for _, m := range ms {
		ge.Members = append(ge.Members, model.MemberDecision{
			FileID: m.f.ID, Path: m.f.PrimaryPath(), Decision: m.dec, Reasons: m.reasons, EdgeToKeeper: m.edge,
		})
		ge.Space.LogicalBytes += m.f.Size * int64(len(m.f.KnownPaths))
		ge.Space.PhysicalBytes += m.f.Size
		switch m.dec {
		case model.DecisionRedundantCandidate:
			candidates++
			ge.Space.PotentialReclaimBytes += m.f.Size
		case model.DecisionManualReview, model.DecisionInsufficientEvidence:
			undecided = true
		}
		for _, e := range ix.EdgesByFile[m.f.ID] {
			if edgeSeen[e.ID] || (e.Relation != model.RelationByteIdentical && e.Relation != model.RelationVisuallySimilar) {
				continue
			}
			edgeSeen[e.ID] = true
			ge.Evidence = append(ge.Evidence, fmt.Sprintf("%s ~ %s [%s]: %s", e.Left, e.Right, e.Relation, strings.Join(e.Evidence, "; ")))
		}
	}
	sort.Strings(ge.Evidence)
	if undecided || candidates == 0 {
		ge.Action = model.ActionReview
	} else {
		ge.Action = model.ActionCandidate
	}
	switch {
	case candidates == 0:
		ge.Space.ReclaimStatus = model.ReclaimUnknown
		ge.Space.Note = "No redundant candidates; reclaimable space depends on manual review. " + ReclaimNote
	case undecided:
		ge.Space.ReclaimStatus = model.ReclaimEstimated
		ge.Space.Note = "Covers redundant candidates only; other members need review. " + ReclaimNote
	default:
		ge.Space.ReclaimStatus = model.ReclaimEstimated
		ge.Space.Note = ReclaimNote
	}
	if ge.Evidence == nil {
		ge.Evidence = []string{}
	}
	return ge
}

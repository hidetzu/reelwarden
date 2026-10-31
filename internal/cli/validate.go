package cli

import (
	"fmt"

	"github.com/hidetzu/reelwarden/internal/model"
)

// validateScan checks the references inside a scan document so that a
// truncated or hand-edited file is rejected instead of crashing report/plan
// or yielding candidates without evidence.
func validateScan(r *model.ScanResult) error {
	switch r.Status {
	case model.StatusComplete, model.StatusPartial, model.StatusCancelled:
	default:
		return fmt.Errorf("unknown status %q", r.Status)
	}
	if r.Params.Mode != model.ModeExact && r.Params.Mode != model.ModeVideo {
		return fmt.Errorf("unknown mode %q", r.Params.Mode)
	}
	files := make(map[string]*model.PhysicalFile, len(r.Files))
	identities := map[string]string{}
	for i := range r.Files {
		f := &r.Files[i]
		if f.ID == "" {
			return fmt.Errorf("files[%d] has no id", i)
		}
		switch f.IdentityStatus {
		case model.IdentityKnown, model.IdentityUnknown, model.IdentityUnconfirmed:
		default:
			return fmt.Errorf("file %q has unknown identity_status %q", f.ID, f.IdentityStatus)
		}
		switch f.HardLinkStatus {
		case model.HardLinkNone, model.HardLinkConfirmed, model.HardLinkUnconfirmed:
		default:
			return fmt.Errorf("file %q has unknown hard_link_status %q", f.ID, f.HardLinkStatus)
		}
		// A trusted keeper must be protected by a root the scan recorded.
		if f.InProtectedLibrary && (!f.Protected || !hasRoot(r.ProtectedRoots, f.ProtectedByRoot)) {
			return fmt.Errorf("file %q is marked in_protected_library without a recorded protected root", f.ID)
		}
		// A confirmed identity belongs to exactly one entity.
		if f.IdentityStatus == model.IdentityKnown && f.Identity != nil {
			k := f.Identity.Key()
			if other, dup := identities[k]; dup {
				return fmt.Errorf("files %q and %q claim the same identity", other, f.ID)
			}
			identities[k] = f.ID
		}
		if files[f.ID] != nil {
			return fmt.Errorf("file id %q appears twice", f.ID)
		}
		if f.PrimaryPath() == "" {
			return fmt.Errorf("file %q has no path", f.ID)
		}
		if f.Size < 0 {
			return fmt.Errorf("file %q has a negative size", f.ID)
		}
		files[f.ID] = f
	}
	edges := make(map[string]*model.MatchEdge, len(r.Edges))
	for i := range r.Edges {
		e := &r.Edges[i]
		if e.ID == "" || edges[e.ID] != nil {
			return fmt.Errorf("edges[%d] has a missing or repeated id", i)
		}
		l, r := files[e.Left], files[e.Right]
		if l == nil || r == nil || l == r {
			return fmt.Errorf("edge %q refers to unknown or identical files", e.ID)
		}
		if e.Relation == model.RelationByteIdentical &&
			(l.Exact == nil || r.Exact == nil || l.Exact.SHA256 == "" || l.Exact.SHA256 != r.Exact.SHA256) {
			return fmt.Errorf("edge %q claims byte_identical without matching SHA-256 values", e.ID)
		}
		edges[e.ID] = e
	}
	for _, g := range r.Groups {
		if len(g.Members) < 2 {
			return fmt.Errorf("group %q has fewer than two members", g.ID)
		}
		seen := map[string]bool{}
		for _, id := range g.Members {
			if files[id] == nil || seen[id] {
				return fmt.Errorf("group %q has an unknown or repeated member %q", g.ID, id)
			}
			seen[id] = true
		}
		for _, id := range g.Edges {
			if edges[id] == nil {
				return fmt.Errorf("group %q refers to unknown edge %q", g.ID, id)
			}
		}
	}
	return nil
}

func hasRoot(roots []string, r string) bool {
	for _, x := range roots {
		if x == r {
			return true
		}
	}
	return false
}

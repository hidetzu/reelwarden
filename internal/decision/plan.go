package decision

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hidetzu/reelwarden/internal/model"
)

// BuildPlan converts an evaluation into a read-only plan document.
func BuildPlan(res *model.ScanResult, ev *model.Evaluation, source string, tool model.ToolInfo) *model.Plan {
	ix := model.NewIndex(res)
	p := &model.Plan{
		SchemaVersion:   model.SchemaVersion,
		Tool:            tool,
		GeneratedAt:     time.Now().UTC(),
		SourceScan:      source,
		ScanGeneratedAt: res.GeneratedAt,
		Policy:          ev.Policy,
		Executable:      false,
		Notice:          model.PlanNotice,
		Groups:          []model.PlanGroup{},
		Summary:         ev.Summary,
		Warnings:        []string{},
	}
	if res.Status != model.StatusComplete {
		p.Warnings = append(p.Warnings, "source scan status is "+res.Status+": some files were not fully processed")
	}
	// Carry over scan warnings that change what the plan can be trusted for.
	counts := map[string]int{}
	for _, w := range res.Warnings {
		switch {
		case strings.HasPrefix(w.Code, "protect_root_"), strings.HasPrefix(w.Code, "root_"):
			p.Warnings = append(p.Warnings, w.Code+": "+w.Path+": "+w.Message)
		case w.Code == "identity_unconfirmed", w.Code == "mount_crossed", w.Code == "path_not_utf8",
			w.Code == "unicode_normalization_conflict", w.Code == "directory_cycle",
			w.Code == "symlink_broken", w.Code == "symlink_unresolved", w.Code == "symlink_cycle",
			w.Code == "symlink_outside_roots", w.Code == "depth_exceeded", w.Code == "excluded_directory_unreadable":
			counts[w.Code]++
		}
	}
	codes := make([]string, 0, len(counts))
	for c := range counts {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s: %d occurrence(s) in the scan; see its warnings", c, counts[c]))
	}
	if res.Params.Mode == model.ModeExact {
		p.Warnings = append(p.Warnings, "exact mode: re-encoded or resized copies were not searched")
	}
	for _, ge := range ev.Groups {
		pg := model.PlanGroup{GroupID: ge.GroupID, Relation: ge.Relation, Action: ge.Action, Space: ge.Space, Actions: []model.PlanAction{}}
		for _, md := range ge.Members {
			f := ix.Files[md.FileID]
			if md.FileID == ge.Keeper && md.Decision == model.DecisionRecommendedKeep {
				pg.Keeper = &model.PlanKeeper{FileID: f.ID, Path: f.PrimaryPath(), KnownPaths: f.KnownPaths, Reasons: md.Reasons}
				continue
			}
			a := model.PlanAction{
				Type:                model.PlanActionReview,
				FileID:              f.ID,
				Decision:            md.Decision,
				Reasons:             md.Reasons,
				AffectedKnownPaths:  f.KnownPaths,
				AffectedSymlinks:    f.SymlinkRefs,
				UnverifiedLinkCount: f.ExternalLinkCount(),
				Protected:           f.Protected,
				Warnings:            []string{},
				Irreversible:        true,
			}
			if md.Decision == model.DecisionRedundantCandidate {
				a.Type = model.PlanActionCandidateRemove
			}
			for _, kp := range f.KnownPaths {
				pc := model.Precondition{Path: kp, Identity: f.Identity, Size: f.Size, MTime: f.MTime, Nlink: f.Nlink}
				if f.Exact != nil {
					pc.SHA256 = f.Exact.SHA256
				}
				a.Preconditions = append(a.Preconditions, pc)
			}
			if len(f.KnownPaths) > 1 {
				a.Warnings = append(a.Warnings, "this entity has several hard-linked paths; space is freed only if every path is removed")
			}
			if f.UnverifiedExternalLinks {
				a.Warnings = append(a.Warnings, "links outside the scanned roots may exist; removing these paths may not free space")
			}
			if f.HiddenLinksPossible {
				a.Warnings = append(a.Warnings, "network filesystem: server-side symlinks and links are invisible here; this path may be the same file as another member")
			}
			if len(f.PossibleLinkRefs) > 0 {
				a.Warnings = append(a.Warnings, "links that cannot be resolved here name this file and may refer to it")
			}
			if len(f.SymlinkRefs) > 0 {
				a.Warnings = append(a.Warnings, "symlinks point to this file and would become broken")
			}
			if f.Exact == nil || f.Exact.SHA256 == "" {
				a.Warnings = append(a.Warnings, "no full SHA-256 recorded; re-verify content before acting")
			}
			if ge.Relation != model.RelationByteIdentical {
				a.Warnings = append(a.Warnings, "content is visually similar, not identical; information may be lost")
				a.Warnings = append(a.Warnings, "only sampled frames were compared: audio, text visible in a few frames and scenes between samples were not checked")
			}
			a.Warnings = append(a.Warnings, "irreversible if executed by an external tool; reelwarden v0.1 never executes it")
			pg.Actions = append(pg.Actions, a)
		}
		p.Groups = append(p.Groups, pg)
	}
	return p
}

package model

import "time"

// MemberDecision is the per-member outcome of evaluating a group.
type MemberDecision struct {
	FileID   string   `json:"file_id"`
	Path     string   `json:"path"`
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons"`
	// EdgeToKeeper is the direct edge between this member and the keeper, if any.
	EdgeToKeeper string `json:"edge_to_keeper,omitempty"`
}

// SpaceEstimate separates the different notions of "size" (docs/design.md §9).
type SpaceEstimate struct {
	LogicalBytes          int64  `json:"logical_bytes"`
	PhysicalBytes         int64  `json:"physical_bytes"`
	PotentialReclaimBytes int64  `json:"potential_reclaim_bytes"`
	ReclaimStatus         string `json:"reclaim_status"`
	Note                  string `json:"note,omitempty"`
}

// GroupEvaluation is the decision output for one group.
type GroupEvaluation struct {
	GroupID       string           `json:"group_id"`
	Relation      string           `json:"relation"`
	Action        string           `json:"action"`
	Keeper        string           `json:"keeper,omitempty"`
	Members       []MemberDecision `json:"members"`
	ReviewReasons []string         `json:"review_reasons,omitempty"`
	Evidence      []string         `json:"evidence"`
	Space         SpaceEstimate    `json:"space"`
}

// Evaluation is the full decision output over a scan.
type Evaluation struct {
	Policy  string            `json:"policy"`
	Groups  []GroupEvaluation `json:"groups"`
	Summary EvaluationSummary `json:"summary"`
}

// EvaluationSummary aggregates decisions.
type EvaluationSummary struct {
	Groups                int   `json:"groups"`
	RecommendedKeep       int   `json:"recommended_keep"`
	RedundantCandidates   int   `json:"redundant_candidates"`
	ManualReview          int   `json:"manual_review"`
	InsufficientEvidence  int   `json:"insufficient_evidence"`
	PotentialReclaimBytes int64 `json:"potential_reclaim_bytes"`
	UnknownReclaimGroups  int   `json:"unknown_reclaim_groups"`
}

// Precondition is what must still be true before any future action is
// executed. The v0.1 tool never executes actions.
type Precondition struct {
	Path     string        `json:"path"`
	Identity *FileIdentity `json:"identity,omitempty"`
	Size     int64         `json:"size"`
	MTime    time.Time     `json:"mtime"`
	SHA256   string        `json:"sha256,omitempty"`
	Nlink    uint64        `json:"nlink,omitempty"`
}

// Plan action types.
const (
	PlanActionReview          = "review"
	PlanActionCandidateRemove = "candidate_remove"
)

// PlanAction is one proposed, unexecuted action.
type PlanAction struct {
	Type                string         `json:"type"`
	FileID              string         `json:"file_id"`
	Decision            string         `json:"decision"`
	Reasons             []string       `json:"reasons"`
	Preconditions       []Precondition `json:"preconditions"`
	AffectedKnownPaths  []string       `json:"affected_known_paths"`
	AffectedSymlinks    []string       `json:"affected_symlinks,omitempty"`
	UnverifiedLinkCount uint64         `json:"unverified_link_count"`
	Protected           bool           `json:"protected"`
	Warnings            []string       `json:"warnings"`
	Irreversible        bool           `json:"irreversible"`
}

// PlanGroup is the plan for one duplicate group.
type PlanGroup struct {
	GroupID  string        `json:"group_id"`
	Relation string        `json:"relation"`
	Action   string        `json:"action"`
	Keeper   *PlanKeeper   `json:"keeper,omitempty"`
	Actions  []PlanAction  `json:"actions"`
	Space    SpaceEstimate `json:"space"`
}

// PlanKeeper identifies the recommended keeper and its references.
type PlanKeeper struct {
	FileID     string   `json:"file_id"`
	Path       string   `json:"path"`
	KnownPaths []string `json:"known_paths"`
	Reasons    []string `json:"reasons"`
}

// Plan is the document written by `reelwarden plan`.
type Plan struct {
	SchemaVersion   string            `json:"schema_version"`
	Tool            ToolInfo          `json:"tool"`
	GeneratedAt     time.Time         `json:"generated_at"`
	SourceScan      string            `json:"source_scan"`
	ScanGeneratedAt time.Time         `json:"scan_generated_at"`
	Policy          string            `json:"policy"`
	Executable      bool              `json:"executable"`
	Notice          string            `json:"notice"`
	Groups          []PlanGroup       `json:"groups"`
	Summary         EvaluationSummary `json:"summary"`
	Warnings        []string          `json:"warnings"`
}

// PlanNotice is written into every plan.
const PlanNotice = "This plan is a proposal only. reelwarden v0.1 does not implement apply, delete, move, trash or relink. Every precondition must be re-verified immediately before any external action. Candidate actions on visually similar files are not deletion approvals."

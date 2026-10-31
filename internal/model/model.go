// Package model defines the versioned result schema shared by every stage
// of reelwarden: inventory, identity, fingerprints, matching, grouping,
// decisions and plans.
//
// The schema deliberately separates three layers (see docs/design.md §4):
//
//   - PathEntry: a directory entry found during the walk.
//   - PhysicalFile: one entity (inode / file ID) that one or more paths reach.
//   - MatchEdge: a content relation between two physical files.
//
// All types are plain data and are serialised as JSON. Field names are
// stable within a SchemaVersion.
package model

import "time"

// SchemaVersion is the version of the JSON documents written by scan and
// plan. Bump it whenever a field changes meaning or is removed.
const SchemaVersion = "1"

// ToolName is the canonical program name.
const ToolName = "reelwarden"

// Scan modes.
const (
	ModeExact = "exact"
	ModeVideo = "video"
)

// Scan status values.
const (
	StatusComplete  = "complete"
	StatusPartial   = "partial"
	StatusCancelled = "cancelled"
)

// PathEntry kinds.
const (
	KindFile    = "file"
	KindSymlink = "symlink"
)

// Symlink status values.
const (
	SymlinkOK           = "ok"
	SymlinkBroken       = "broken"
	SymlinkOutsideRoots = "outside_roots"
	SymlinkDirectory    = "directory"
	SymlinkCycle        = "cycle"
	SymlinkUnresolved   = "unresolved"
)

// SymlinkFormatMinshallFrench marks a symlink stored as an XSym file.
const SymlinkFormatMinshallFrench = "minshall-french"

// Identity status values.
const (
	IdentityKnown   = "known"
	IdentityUnknown = "unknown"
	// IdentityUnconfirmed: the OS reported an identity, but the filesystem
	// (network, FUSE, overlay, unknown) cannot be trusted to keep it unique
	// and stable. Paths are never merged on such an identity.
	IdentityUnconfirmed = "unconfirmed"
)

// Hard-link status values.
const (
	HardLinkNone        = "none"        // one path, link count 1, trusted filesystem
	HardLinkConfirmed   = "confirmed"   // several paths or nlink > 1 on a trusted filesystem
	HardLinkUnconfirmed = "unconfirmed" // the filesystem cannot tell
)

// Identity confidence values.
const (
	ConfidenceHigh    = "high"
	ConfidenceLow     = "low"
	ConfidenceUnknown = "unknown"
)

// MatchEdge relations (docs/design.md §4).
const (
	RelationSameFileAlias   = "same_file_alias"
	RelationByteIdentical   = "byte_identical"
	RelationVisuallySimilar = "visually_similar"
	RelationPartialOverlap  = "partial_overlap"
	RelationUncertain       = "uncertain"
	RelationMixed           = "mixed"
)

// Decision values per group member (docs/design.md §9).
const (
	DecisionRecommendedKeep      = "recommended_keep"
	DecisionRedundantCandidate   = "redundant_candidate"
	DecisionManualReview         = "manual_review"
	DecisionInsufficientEvidence = "insufficient_evidence"
)

// Group-level actions.
const (
	// ActionReview: at least one member needs a human decision.
	ActionReview = "REVIEW"
	// ActionCandidate: every non-keeper member is a redundant candidate.
	ActionCandidate = "CANDIDATE"
)

// Reclaim status values.
const (
	ReclaimEstimated = "estimated"
	ReclaimUnknown   = "unknown"
	ReclaimNone      = "none"
)

// Policies.
const (
	PolicyConservative = "conservative"
	PolicyBalanced     = "balanced"
)

// ToolInfo identifies the program that produced a document.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	GoOS    string `json:"go_os"`
	GoArch  string `json:"go_arch"`
}

// ScanRoot is one directory given on the command line.
type ScanRoot struct {
	Index              int    `json:"index"`
	Path               string `json:"path"`
	Filesystem         string `json:"filesystem,omitempty"`
	NetworkFilesystem  bool   `json:"network_filesystem"`
	IdentityConfidence string `json:"identity_confidence"`
	Error              string `json:"error,omitempty"`
}

// ScanParams records every parameter that influences results.
type ScanParams struct {
	Mode            string        `json:"mode"`
	Extensions      []string      `json:"extensions"`
	Excludes        []string      `json:"excludes,omitempty"`
	FollowSymlinks  bool          `json:"follow_symlinks"`
	IOWorkers       int           `json:"io_workers"`
	MediaWorkers    int           `json:"media_workers"`
	PartialHashSize int64         `json:"partial_hash_size"`
	Visual          *VisualParams `json:"visual,omitempty"`
	Match           *MatchParams  `json:"match,omitempty"`
	FFmpegVersion   string        `json:"ffmpeg_version,omitempty"`
	FFprobeVersion  string        `json:"ffprobe_version,omitempty"`
	CacheEnabled    bool          `json:"cache_enabled"`
}

// VisualParams are the sampling parameters of visual fingerprints.
type VisualParams struct {
	Algorithm        string  `json:"algorithm"`
	AlgorithmVersion int     `json:"algorithm_version"`
	Samples          int     `json:"samples"`
	Width            int     `json:"width"`
	Height           int     `json:"height"`
	LowInfoStdDev    float64 `json:"low_info_stddev"`
	LowInfoMean      float64 `json:"low_info_mean"`
}

// MatchParams are the thresholds used in pair validation.
type MatchParams struct {
	DurationToleranceSeconds float64 `json:"duration_tolerance_seconds"`
	DurationToleranceRatio   float64 `json:"duration_tolerance_ratio"`
	FrameHammingThreshold    int     `json:"frame_hamming_threshold"`
	MinComparableFrames      int     `json:"min_comparable_frames"`
	SimilarMatchRatio        float64 `json:"similar_match_ratio"`
	UncertainMatchRatio      float64 `json:"uncertain_match_ratio"`
	MaxMeanHamming           float64 `json:"max_mean_hamming"`
	// MaxColorDelta is the largest ColorDelta at which balanced may still
	// propose a visually similar copy.
	MaxColorDelta float64 `json:"max_color_delta"`
}

// PathEntry is one directory entry (regular file or symlink) found in the walk.
type PathEntry struct {
	ID              string `json:"id"`
	Path            string `json:"path"`
	RootIndex       int    `json:"root_index"`
	Kind            string `json:"kind"`
	PhysicalFileID  string `json:"physical_file_id,omitempty"`
	SymlinkTarget   string `json:"symlink_target,omitempty"`
	SymlinkResolved string `json:"symlink_resolved,omitempty"`
	SymlinkStatus   string `json:"symlink_status,omitempty"`
	// SymlinkFormat is "minshall-french" for an XSym file (an SMB symlink
	// stored as a regular file); empty for a real symlink.
	SymlinkFormat string   `json:"symlink_format,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// FileIdentity is the OS-level identity of an entity.
type FileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Key returns a stable string key for maps and the cache.
func (id FileIdentity) Key() string {
	return formatIdentity(id.Device, id.Inode)
}

// ExactFingerprint is the result of exact hashing.
type ExactFingerprint struct {
	PartialSHA256 string `json:"partial_sha256,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	FromCache     bool   `json:"from_cache,omitempty"`
}

// FrameSample is one sampled frame of a visual fingerprint.
type FrameSample struct {
	Index   int     `json:"index"`
	TimeSec float64 `json:"time_sec"`
	DHash   uint64  `json:"dhash"`
	Mean    float64 `json:"mean"`
	StdDev  float64 `json:"stddev"`
	LowInfo bool    `json:"low_info"`
	// Mean Cb and Cr (BT.601, -128..128) and mean chroma magnitude of the
	// sampled frame; all zero for a greyscale picture.
	Cb     float64 `json:"cb"`
	Cr     float64 `json:"cr"`
	Chroma float64 `json:"chroma"`
	// CellCbCr holds mean Cb, Cr pairs for each cell of a 3x3 grid, row by row.
	CellCbCr []float64 `json:"cell_cbcr,omitempty"`
	Failed   bool      `json:"failed,omitempty"`
}

// VisualFingerprint is the sampled perceptual signature of an entity.
type VisualFingerprint struct {
	Params        VisualParams  `json:"params"`
	FFmpegVersion string        `json:"ffmpeg_version,omitempty"`
	Frames        []FrameSample `json:"frames"`
	LowInfoCount  int           `json:"low_info_count"`
	FailedCount   int           `json:"failed_count"`
	FromCache     bool          `json:"from_cache,omitempty"`
}

// InformativeCount returns the number of frames usable for comparison.
func (v *VisualFingerprint) InformativeCount() int {
	if v == nil {
		return 0
	}
	n := 0
	for _, f := range v.Frames {
		if !f.LowInfo && !f.Failed {
			n++
		}
	}
	return n
}

// StreamInfo is one media stream as reported by ffprobe.
type StreamInfo struct {
	Index          int               `json:"index"`
	Type           string            `json:"type"`
	Codec          string            `json:"codec,omitempty"`
	Profile        string            `json:"profile,omitempty"`
	Width          int               `json:"width,omitempty"`
	Height         int               `json:"height,omitempty"`
	Rotation       int               `json:"rotation,omitempty"`
	PixelFormat    string            `json:"pixel_format,omitempty"`
	BitDepth       int               `json:"bit_depth,omitempty"`
	ColorPrimaries string            `json:"color_primaries,omitempty"`
	ColorTransfer  string            `json:"color_transfer,omitempty"`
	ColorSpace     string            `json:"color_space,omitempty"`
	HDR            bool              `json:"hdr,omitempty"`
	FrameRate      float64           `json:"frame_rate,omitempty"`
	AvgFrameRate   float64           `json:"avg_frame_rate,omitempty"`
	BitRate        int64             `json:"bit_rate,omitempty"`
	Channels       int               `json:"channels,omitempty"`
	ChannelLayout  string            `json:"channel_layout,omitempty"`
	SampleRate     int               `json:"sample_rate,omitempty"`
	Language       string            `json:"language,omitempty"`
	Title          string            `json:"title,omitempty"`
	Default        bool              `json:"default,omitempty"`
	Attached       bool              `json:"attached_pic,omitempty"`
	Tags           map[string]string `json:"-"`
}

// MediaInfo is the parsed ffprobe result for an entity.
type MediaInfo struct {
	FormatName      string       `json:"format_name,omitempty"`
	FormatLongName  string       `json:"format_long_name,omitempty"`
	DurationSec     float64      `json:"duration_sec"`
	DurationKnown   bool         `json:"duration_known"`
	BitRate         int64        `json:"bit_rate,omitempty"`
	Streams         []StreamInfo `json:"streams"`
	VideoStreams    int          `json:"video_streams"`
	AudioStreams    int          `json:"audio_streams"`
	SubtitleStreams int          `json:"subtitle_streams"`
	Chapters        int          `json:"chapters"`
	// Attachments counts cover art (attached_pic) and Matroska attachments.
	Attachments int `json:"attachments"`
	// DataStreams counts data streams such as telemetry or timecode.
	DataStreams int    `json:"data_streams"`
	ProbeError  string `json:"probe_error,omitempty"`
	FromCache   bool   `json:"from_cache,omitempty"`
}

// PrimaryVideo returns the first non-attached-picture video stream, or nil.
func (m *MediaInfo) PrimaryVideo() *StreamInfo {
	if m == nil {
		return nil
	}
	for i := range m.Streams {
		s := &m.Streams[i]
		if s.Type == "video" && !s.Attached {
			return s
		}
	}
	return nil
}

// PhysicalFile is one entity reached by one or more paths.
type PhysicalFile struct {
	ID                      string        `json:"id"`
	IdentityStatus          string        `json:"identity_status"`
	IdentityConfidence      string        `json:"identity_confidence"`
	Identity                *FileIdentity `json:"identity,omitempty"`
	Nlink                   uint64        `json:"nlink"`
	NlinkKnown              bool          `json:"nlink_known"`
	KnownPaths              []string      `json:"known_paths"`
	SymlinkRefs             []string      `json:"symlink_refs,omitempty"`
	UnverifiedExternalLinks bool          `json:"unverified_external_links"`
	Size                    int64         `json:"size"`
	MTime                   time.Time     `json:"mtime"`
	Protected               bool          `json:"protected"`
	ProtectedByRoot         string        `json:"protected_by_root,omitempty"`
	// InProtectedLibrary is set when a path of this file was read as a video
	// by the walk and its real location lies under a protected root. Only
	// such a file can be the keeper that lets other copies be proposed;
	// Protected alone (also set from identity, for files reached in other
	// ways) only shields a file from being proposed.
	InProtectedLibrary bool               `json:"in_protected_library,omitempty"`
	ChangedDuringScan  bool               `json:"changed_during_scan,omitempty"`
	Exact              *ExactFingerprint  `json:"exact,omitempty"`
	Visual             *VisualFingerprint `json:"visual,omitempty"`
	Media              *MediaInfo         `json:"media,omitempty"`
	Errors             []string           `json:"errors,omitempty"`
	// PathsNotUTF8 is set when a known path or symlink reference is not valid
	// UTF-8. JSON cannot carry such names exactly, so distinct paths may look
	// identical in the output; decisions treat the file as insufficient evidence.
	PathsNotUTF8 bool `json:"paths_not_utf8,omitempty"`
	// UnicodeConflict is set when a path of this file differs from another
	// scanned path only in Unicode normalization (NFC vs NFD). The two look
	// identical when shown, and SMB or macOS may map them to one file.
	UnicodeConflict bool `json:"unicode_conflict,omitempty"`
	// PossibleLinkRefs lists links that could not be resolved here (broken,
	// unresolvable, cyclic) whose target names this file. An absolute target
	// valid only in a container or on another machine may still mean it.
	PossibleLinkRefs []string `json:"possible_link_refs,omitempty"`
	// HardLinkStatus tells whether hard links of this file are known to exist.
	HardLinkStatus string `json:"hard_link_status"`
	// HiddenLinksPossible is set on network filesystems (CIFS/SMB, NFS, FUSE):
	// the server can resolve symlinks and links the client never sees, so
	// another path may be this very file whatever identities are reported.
	HiddenLinksPossible bool `json:"hidden_links_possible,omitempty"`
	// SameIdentityAs lists other files that reported the same identity on an
	// untrusted filesystem. They may be one file (a hard link, or the same
	// file reached through two shares) or different files.
	SameIdentityAs []string `json:"same_identity_as,omitempty"`
	// CTimeUnixNano is the inode change time used to validate cache entries
	// (0 when unknown). It is not part of the schema.
	CTimeUnixNano int64 `json:"-"`
}

// PrimaryPath returns the first known path, or the first symlink ref.
func (p *PhysicalFile) PrimaryPath() string {
	if len(p.KnownPaths) > 0 {
		return p.KnownPaths[0]
	}
	if len(p.SymlinkRefs) > 0 {
		return p.SymlinkRefs[0]
	}
	return ""
}

// ExternalLinkCount returns nlink minus the known paths, or 0 if unknown.
func (p *PhysicalFile) ExternalLinkCount() uint64 {
	if !p.NlinkKnown || p.Nlink <= uint64(len(p.KnownPaths)) {
		return 0
	}
	return p.Nlink - uint64(len(p.KnownPaths))
}

// VisualMetrics are the pair-validation measurements for a visual edge.
type VisualMetrics struct {
	ComparableFrames     int     `json:"comparable_frames"`
	MatchingFrames       int     `json:"matching_frames"`
	MatchRatio           float64 `json:"match_ratio"`
	MeanHamming          float64 `json:"mean_hamming"`
	LeftLowInfoRatio     float64 `json:"left_low_info_ratio"`
	RightLowInfoRatio    float64 `json:"right_low_info_ratio"`
	DurationDeltaSeconds float64 `json:"duration_delta_seconds"`
	// ColorDelta is the mean, over comparable frames, of the per-cell Cb/Cr
	// distance (or the whole-frame one for fingerprints without cells) plus
	// the difference in chroma magnitude.
	ColorDelta float64 `json:"color_delta"`
}

// MatchEdge is a content relation between two physical files.
type MatchEdge struct {
	ID         string         `json:"id"`
	Left       string         `json:"left"`
	Right      string         `json:"right"`
	Relation   string         `json:"relation"`
	Confidence string         `json:"confidence"`
	Evidence   []string       `json:"evidence"`
	Visual     *VisualMetrics `json:"visual,omitempty"`
}

// Other returns the member on the other side of the edge from id.
func (e *MatchEdge) Other(id string) (string, bool) {
	switch id {
	case e.Left:
		return e.Right, true
	case e.Right:
		return e.Left, true
	}
	return "", false
}

// DuplicateGroup is a connected component of byte_identical and
// visually_similar edges.
type DuplicateGroup struct {
	ID       string   `json:"id"`
	Relation string   `json:"relation"`
	Members  []string `json:"members"`
	Edges    []string `json:"edges"`
}

// Warning is a non-fatal problem encountered during the scan.
type Warning struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// ScanStats summarises the work done.
type ScanStats struct {
	DirectoriesWalked  int     `json:"directories_walked"`
	EntriesFound       int     `json:"entries_found"`
	Files              int     `json:"files"`
	Symlinks           int     `json:"symlinks"`
	PhysicalFiles      int     `json:"physical_files"`
	HardlinkAliases    int     `json:"hardlink_aliases"`
	PartialHashes      int     `json:"partial_hashes"`
	FullHashes         int     `json:"full_hashes"`
	Probed             int     `json:"probed"`
	Fingerprinted      int     `json:"fingerprinted"`
	CacheHits          int     `json:"cache_hits"`
	Failures           int     `json:"failures"`
	ByteIdenticalEdges int     `json:"byte_identical_edges"`
	VisualEdges        int     `json:"visual_edges"`
	UncertainEdges     int     `json:"uncertain_edges"`
	Groups             int     `json:"groups"`
	LogicalBytes       int64   `json:"logical_bytes"`
	PhysicalBytes      int64   `json:"physical_bytes"`
	ElapsedSeconds     float64 `json:"elapsed_seconds"`
}

// ScanResult is the document written by `reelwarden scan`.
type ScanResult struct {
	SchemaVersion  string           `json:"schema_version"`
	Tool           ToolInfo         `json:"tool"`
	GeneratedAt    time.Time        `json:"generated_at"`
	Status         string           `json:"status"`
	Roots          []ScanRoot       `json:"roots"`
	ProtectedRoots []string         `json:"protected_roots,omitempty"`
	Params         ScanParams       `json:"params"`
	Entries        []PathEntry      `json:"entries"`
	Files          []PhysicalFile   `json:"files"`
	Edges          []MatchEdge      `json:"edges"`
	Groups         []DuplicateGroup `json:"groups"`
	Warnings       []Warning        `json:"warnings"`
	Stats          ScanStats        `json:"stats"`
	Notice         string           `json:"notice"`
}

// ReadOnlyNotice is embedded in every document.
const ReadOnlyNotice = "No files were modified. This document may contain absolute paths of private files; treat it as sensitive."

// Index builds lookup maps over a scan result.
type Index struct {
	Files   map[string]*PhysicalFile
	Entries map[string]*PathEntry
	Edges   map[string]*MatchEdge
	// EdgesByFile maps a physical file ID to the edges touching it.
	EdgesByFile map[string][]*MatchEdge
	byPair      map[[2]string]*MatchEdge
}

// NewIndex builds an Index over r. The maps point into r's slices.
func NewIndex(r *ScanResult) *Index {
	ix := &Index{
		Files:       make(map[string]*PhysicalFile, len(r.Files)),
		Entries:     make(map[string]*PathEntry, len(r.Entries)),
		Edges:       make(map[string]*MatchEdge, len(r.Edges)),
		EdgesByFile: make(map[string][]*MatchEdge),
		byPair:      make(map[[2]string]*MatchEdge),
	}
	for i := range r.Files {
		ix.Files[r.Files[i].ID] = &r.Files[i]
	}
	for i := range r.Entries {
		ix.Entries[r.Entries[i].ID] = &r.Entries[i]
	}
	for i := range r.Edges {
		e := &r.Edges[i]
		ix.Edges[e.ID] = e
		ix.EdgesByFile[e.Left] = append(ix.EdgesByFile[e.Left], e)
		ix.EdgesByFile[e.Right] = append(ix.EdgesByFile[e.Right], e)
		if _, dup := ix.byPair[pair(e.Left, e.Right)]; !dup {
			ix.byPair[pair(e.Left, e.Right)] = e
		}
	}
	return ix
}

// EdgeBetween returns the direct edge between a and b, if any.
func (ix *Index) EdgeBetween(a, b string) *MatchEdge {
	return ix.byPair[pair(a, b)]
}

func pair(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

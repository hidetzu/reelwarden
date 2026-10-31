// Package report renders a scan result and its evaluation as a human
// table, a JSON document or CSV rows.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/quality"
)

// Formats.
const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatCSV   = "csv"
)

// Document is the JSON report.
type Document struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          model.ToolInfo    `json:"tool"`
	GeneratedAt   time.Time         `json:"generated_at"`
	SourceScan    string            `json:"source_scan"`
	ScanStatus    string            `json:"scan_status"`
	ScanMode      string            `json:"scan_mode"`
	Stats         model.ScanStats   `json:"stats"`
	Evaluation    *model.Evaluation `json:"evaluation"`
	Uncertain     []model.MatchEdge `json:"uncertain_edges"`
	Warnings      []model.Warning   `json:"warnings"`
	Notice        string            `json:"notice"`
}

// Write renders in the requested format.
func Write(w io.Writer, format string, res *model.ScanResult, ev *model.Evaluation, source string, tool model.ToolInfo) error {
	switch format {
	case FormatTable, "":
		return Table(w, res, ev)
	case FormatJSON:
		doc := Document{
			SchemaVersion: model.SchemaVersion, Tool: tool, GeneratedAt: time.Now().UTC(),
			SourceScan: source, ScanStatus: res.Status, ScanMode: res.Params.Mode, Stats: res.Stats,
			Evaluation: ev, Uncertain: uncertain(res), Warnings: res.Warnings, Notice: model.ReadOnlyNotice,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case FormatCSV:
		return CSV(w, res, ev)
	}
	return fmt.Errorf("unknown format %q (use table, json or csv)", format)
}

func uncertain(res *model.ScanResult) []model.MatchEdge {
	out := []model.MatchEdge{}
	for _, e := range res.Edges {
		if e.Relation == model.RelationUncertain {
			out = append(out, e)
		}
	}
	return out
}

// HumanBytes formats a byte count with binary units.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func label(dec string) string {
	switch dec {
	case model.DecisionRecommendedKeep:
		return "KEEP CANDIDATE"
	case model.DecisionRedundantCandidate:
		return "REDUNDANT CANDIDATE"
	case model.DecisionManualReview:
		return "NEEDS REVIEW"
	case model.DecisionInsufficientEvidence:
		return "INSUFFICIENT EVIDENCE"
	}
	return strings.ToUpper(dec)
}

// Table writes the human-readable report.
func Table(w io.Writer, res *model.ScanResult, ev *model.Evaluation) error {
	ix := model.NewIndex(res)
	bw := &errWriter{w: w}
	p := bw.printf
	st := res.Stats
	p("reelwarden report | mode: %s | status: %s | policy: %s\n", res.Params.Mode, res.Status, ev.Policy)
	p("Paths: %d files, %d symlinks | Physical files: %d (%d hard-link aliases)\n", st.Files, st.Symlinks, st.PhysicalFiles, st.HardlinkAliases)
	p("Logical size (paths): %s | Physical size (entities found): %s\n", HumanBytes(st.LogicalBytes), HumanBytes(st.PhysicalBytes))
	p("Edges: %d byte-identical, %d visually similar, %d uncertain | Groups: %d | Failures: %d\n",
		st.ByteIdenticalEdges, st.VisualEdges, st.UncertainEdges, st.Groups, st.Failures)
	if res.Params.Mode == model.ModeExact {
		p("Note: exact mode only finds byte-identical copies; re-encodes were not searched.\n")
	}
	for _, g := range ev.Groups {
		p("\n%s\n", strings.Repeat("=", 72))
		p("Group %s | relationship: %s | action: %s\n", g.GroupID, g.Relation, g.Action)
		members := append([]model.MemberDecision(nil), g.Members...)
		sort.SliceStable(members, func(i, j int) bool { return members[i].FileID == g.Keeper && members[j].FileID != g.Keeper })
		for _, m := range members {
			f := ix.Files[m.FileID]
			role := label(m.Decision)
			if m.FileID == g.Keeper && m.Decision != model.DecisionRecommendedKeep {
				role = "KEEP CANDIDATE (unconfirmed)"
			}
			p("\n%s: %s\n", role, f.PrimaryPath())
			p("  %s | %s\n", HumanBytes(f.Size), quality.ProfileOf(f).Summary())
			if f.Protected {
				p("  protected by: %s\n", f.ProtectedByRoot)
			}
			if len(f.KnownPaths) > 1 || len(f.SymlinkRefs) > 0 {
				p("  Links found:\n")
				for _, kp := range f.KnownPaths[1:] {
					p("    %s  [hardlink]\n", kp)
				}
				for _, sr := range f.SymlinkRefs {
					p("    %s  [symlink]\n", sr)
				}
			}
			if f.UnverifiedExternalLinks {
				if n := f.ExternalLinkCount(); n > 0 {
					p("  ! %d hard link(s) not found among scanned paths (outside the roots, or in hidden, excluded or bin folders; nlink=%d)\n", n, f.Nlink)
				} else {
					p("  ! link count cannot be verified on this filesystem\n")
				}
			}
			for _, r := range m.Reasons {
				p("  - %s\n", r)
			}
		}
		p("\nEvidence:\n")
		for _, e := range g.Evidence {
			p("  - %s\n", e)
		}
		p("\nDecision: %s\n", g.Action)
		if len(g.ReviewReasons) > 0 {
			p("Review reasons: %s\n", strings.Join(g.ReviewReasons, ", "))
		}
		switch g.Space.ReclaimStatus {
		case model.ReclaimEstimated:
			p("Potential reclaimable space: %s (estimated)\n", HumanBytes(g.Space.PotentialReclaimBytes))
		default:
			p("Potential reclaimable space: UNKNOWN\n")
		}
		p("  %s\n", g.Space.Note)
	}
	if un := uncertain(res); len(un) > 0 {
		p("\n%s\nUncertain pairs (not grouped, no decision):\n", strings.Repeat("=", 72))
		for _, e := range un {
			p("  %s <-> %s\n    %s\n", ix.Files[e.Left].PrimaryPath(), ix.Files[e.Right].PrimaryPath(), strings.Join(e.Evidence, "; "))
		}
	}
	if len(res.Warnings) > 0 {
		p("\n%s\nWarnings (%d):\n", strings.Repeat("=", 72), len(res.Warnings))
		for _, wr := range res.Warnings {
			p("  [%s] %s: %s\n", wr.Code, wr.Path, wr.Message)
		}
	}
	s := ev.Summary
	p("\nSummary: %d groups | keep %d | redundant candidates %d | review %d | insufficient evidence %d\n",
		s.Groups, s.RecommendedKeep, s.RedundantCandidates, s.ManualReview, s.InsufficientEvidence)
	p("Potential reclaimable space (candidates only): %s; %d group(s) with unknown reclaim\n", HumanBytes(s.PotentialReclaimBytes), s.UnknownReclaimGroups)
	if len(res.ProtectedRoots) == 0 && s.Groups > 0 {
		p("No --protect-root was given, so no copy is proposed. Rescan with --protect-root for the library you trust.\n")
	}
	p("No files were modified.\n")
	return bw.err
}

type errWriter struct {
	w   io.Writer
	err error
}

// printf writes to the terminal-oriented table. String arguments that hold
// control characters (newlines, ANSI escapes in file names) are quoted so
// they cannot fake lines or colours.
func (e *errWriter) printf(f string, a ...any) {
	if e.err != nil {
		return
	}
	for i, v := range a {
		if s, ok := v.(string); ok && strings.IndexFunc(s, unicode.IsControl) >= 0 {
			a[i] = strconv.Quote(s)
		}
	}
	_, e.err = fmt.Fprintf(e.w, f, a...)
}

// CSVHeader is the column list of the CSV report.
var CSVHeader = []string{
	"group_id", "group_relation", "group_action", "file_id", "decision", "path", "path_kind",
	"size_bytes", "nlink", "known_paths", "unverified_external_links", "protected",
	"width", "height", "video_codec", "video_bitrate", "frame_rate", "duration_sec",
	"audio_tracks", "subtitle_tracks", "hdr", "sha256", "reasons",
}

// CSV writes one row per path (primary, hard-link alias, symlink) per member.
func CSV(w io.Writer, res *model.ScanResult, ev *model.Evaluation) error {
	ix := model.NewIndex(res)
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, g := range ev.Groups {
		for _, m := range g.Members {
			f := ix.Files[m.FileID]
			pr := quality.ProfileOf(f)
			sha := ""
			if f.Exact != nil {
				sha = f.Exact.SHA256
			}
			base := func(path, kind string) []string {
				return []string{
					g.GroupID, g.Relation, g.Action, f.ID, m.Decision, sanitize(path), kind,
					strconv.FormatInt(f.Size, 10), strconv.FormatUint(f.Nlink, 10), strconv.Itoa(len(f.KnownPaths)),
					strconv.FormatBool(f.UnverifiedExternalLinks), strconv.FormatBool(f.Protected),
					itoa(pr.Width), itoa(pr.Height), pr.Codec, i64(pr.VideoBitRate), ftoa(pr.FrameRate), ftoa(pr.DurationSec),
					probed(f, pr.AudioStreams), probed(f, pr.Subtitles), probedBool(f, pr.HDR), sha,
					sanitize(strings.Join(m.Reasons, "; ")),
				}
			}
			for i, kp := range f.KnownPaths {
				kind := "path"
				if i > 0 {
					kind = model.RelationSameFileAlias
				}
				if err := cw.Write(base(kp, kind)); err != nil {
					return err
				}
			}
			for _, sr := range f.SymlinkRefs {
				if err := cw.Write(base(sr, "symlink")); err != nil {
					return err
				}
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// sanitize neutralises spreadsheet formula injection in cells.
func sanitize(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// probed formats a count measured by ffprobe: "0" means none was found,
// empty means the file was not probed or ffprobe failed on it.
func probed(f *model.PhysicalFile, n int) string {
	if f.Media == nil || f.Media.ProbeError != "" {
		return ""
	}
	return strconv.Itoa(n)
}

func probedBool(f *model.PhysicalFile, b bool) string {
	if f.Media == nil || f.Media.ProbeError != "" {
		return ""
	}
	return strconv.FormatBool(b)
}

func itoa(i int) string {
	if i == 0 {
		return ""
	}
	return strconv.Itoa(i)
}

func i64(i int64) string {
	if i == 0 {
		return ""
	}
	return strconv.FormatInt(i, 10)
}

func ftoa(f float64) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

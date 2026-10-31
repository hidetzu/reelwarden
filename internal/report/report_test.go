package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
)

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 30: "5.0 GiB"} {
		if got := HumanBytes(in); got != want {
			t.Errorf("%d: %s want %s", in, got, want)
		}
	}
}

func sample() (*model.ScanResult, *model.Evaluation) {
	res := &model.ScanResult{
		Params: model.ScanParams{Mode: model.ModeExact},
		Files: []model.PhysicalFile{
			{ID: "f1", KnownPaths: []string{"/a/=cmd|x.mp4", "/a/link.mp4"}, SymlinkRefs: []string{"/a/s.mp4"}, Size: 10, Nlink: 2, NlinkKnown: true},
			{ID: "f2", KnownPaths: []string{"/b/c.mp4"}, Size: 10, Nlink: 3, NlinkKnown: true, UnverifiedExternalLinks: true},
		},
		Edges:  []model.MatchEdge{{ID: "m1", Left: "f1", Right: "f2", Relation: model.RelationByteIdentical, Evidence: []string{"sha"}}},
		Groups: []model.DuplicateGroup{{ID: "g1", Relation: model.RelationByteIdentical, Members: []string{"f1", "f2"}, Edges: []string{"m1"}}},
	}
	ev := &model.Evaluation{Policy: "conservative", Groups: []model.GroupEvaluation{{
		GroupID: "g1", Relation: model.RelationByteIdentical, Action: model.ActionReview, Keeper: "f1",
		Members: []model.MemberDecision{
			{FileID: "f1", Path: "/a/=cmd|x.mp4", Decision: model.DecisionRecommendedKeep, Reasons: []string{"k"}},
			{FileID: "f2", Path: "/b/c.mp4", Decision: model.DecisionManualReview, Reasons: []string{"-unverified"}},
		},
		Space: model.SpaceEstimate{ReclaimStatus: model.ReclaimUnknown, Note: "n"},
	}}}
	return res, ev
}

func TestCSVRowsPerPathAndSanitized(t *testing.T) {
	res, ev := sample()
	var b bytes.Buffer
	if err := CSV(&b, res, ev); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1+3+1 {
		t.Fatalf("rows %d: %v", len(rows), rows)
	}
	kinds := []string{rows[1][6], rows[2][6], rows[3][6], rows[4][6]}
	if strings.Join(kinds, ",") != "path,same_file_alias,symlink,path" {
		t.Errorf("kinds %v", kinds)
	}
	if rows[4][len(rows[4])-1] != "'-unverified" {
		t.Errorf("reasons cell not sanitized: %q", rows[4][len(rows[4])-1])
	}
}

func TestTableMentionsLinksAndReadOnly(t *testing.T) {
	res, ev := sample()
	var b bytes.Buffer
	if err := Table(&b, res, ev); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"[hardlink]", "[symlink]", "not found among scanned paths", "UNKNOWN", "No files were modified.", "exact mode only"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	res, ev := sample()
	if err := Write(&bytes.Buffer{}, "xml", res, ev, "s", model.ToolInfo{}); err == nil {
		t.Error("expected error")
	}
}

func TestTableQuotesControlCharacters(t *testing.T) {
	var b strings.Builder
	w := &errWriter{w: &b}
	w.printf("%s: %s\n", "REDUNDANT CANDIDATE", "/r/movie (1)\nNEEDS REVIEW: keep.mp4\x1b[31m")
	if strings.Count(b.String(), "\n") != 1 || strings.Contains(b.String(), "\x1b") {
		t.Fatalf("control characters reached the table: %q", b.String())
	}
}

package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidetzu/reelwarden/internal/decision"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
)

// Several paths reaching one entity (hard links, a symlink) count once as
// physical data, and only an independent copy can be reclaimed.
func TestCapacityCountsEachEntityOnce(t *testing.T) {
	const size = 4096
	data := strings.Repeat("v", size)
	dir := t.TempDir()
	e1 := filepath.Join(dir, "lib", "a.mp4")
	write(t, e1, data)
	for _, p := range []string{filepath.Join(dir, "lib", "k1", "a.mp4"), filepath.Join(dir, "lib", "k2", "a.mp4")} {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Link(e1, p); err != nil {
			t.Skipf("hard links unsupported: %v", err)
		}
	}
	if err := os.Symlink(e1, filepath.Join(dir, "lib", "link.mp4")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	copyPath := filepath.Join(dir, "backup", "a-copy.mp4")
	write(t, copyPath, data)

	res, err := Run(context.Background(), Options{Scan: scan.Options{Roots: []string{dir}, ProtectRoots: []string{filepath.Join(dir, "lib")}}, Mode: model.ModeExact})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Stats
	if st.PhysicalFiles != 2 || st.HardlinkAliases != 2 {
		t.Fatalf("entities %d, aliases %d; want 2 and 2", st.PhysicalFiles, st.HardlinkAliases)
	}
	if st.PhysicalBytes != 2*size {
		t.Errorf("physical bytes %d, want %d (each entity once)", st.PhysicalBytes, 2*size)
	}
	if st.LogicalBytes != 4*size {
		t.Errorf("logical bytes %d, want %d (3 hard-link paths + the copy; symlinks add nothing)", st.LogicalBytes, 4*size)
	}

	ev, err := decision.Evaluate(res, model.PolicyConservative)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Groups) != 1 {
		t.Fatalf("groups: %+v", ev.Groups)
	}
	sp := ev.Groups[0].Space
	if sp.PotentialReclaimBytes != size || sp.ReclaimStatus != model.ReclaimEstimated {
		t.Errorf("reclaim %d (%s), want %d: only the independent copy", sp.PotentialReclaimBytes, sp.ReclaimStatus, size)
	}
	for _, m := range ev.Groups[0].Members {
		if m.Decision == model.DecisionRedundantCandidate && m.Path != copyPath {
			t.Errorf("the linked entity was proposed: %+v", m)
		}
	}
	if ev.Summary.PotentialReclaimBytes != size {
		t.Errorf("summary reclaim %d, want %d", ev.Summary.PotentialReclaimBytes, size)
	}
}

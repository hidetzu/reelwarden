package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hidetzu/reelwarden/internal/decision"
	"github.com/hidetzu/reelwarden/internal/engine"
	"github.com/hidetzu/reelwarden/internal/filesystem"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/scan"
)

// On CIFS the server can resolve a symlink itself, so the client sees two
// regular files and no link. Two shapes follow, both tested here:
//
//   - serverino: both paths report the server's inode, e.g. dev 69, inode
//     23226, nlink 1. nlink=1 rules out a hard link; the paths may be one
//     file behind a server-side symlink, or two files.
//   - noserverino: the client invents inode numbers, so one server file
//     reached through two paths reports two different identities.
//
// Expected in both: same-file identity and hard link unconfirmed, hidden
// links flagged, no path proposed for deletion, reclaimable bytes unknown.
func TestCIFSServerSideLinksAreNeverTrusted(t *testing.T) {
	cases := []struct {
		name   string
		inodeA uint64
		inodeB uint64
	}{
		{"serverino, same inode", 23226, 23226},
		{"noserverino, client-made inodes", 23226, 23227},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fileA := filepath.Join(dir, "share1", "fileA.mp4")
			fileB := filepath.Join(dir, "share2", "fileB.mp4")
			for _, p := range []string{fileA, fileB} {
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				// Same bytes, as when both paths reach one file on the server.
				if err := os.WriteFile(p, []byte("same video bytes"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			inode := map[string]uint64{fileA: tc.inodeA, fileB: tc.inodeB}
			cifs := filesystem.RootInfo{Filesystem: "cifs", Network: true, Confidence: model.ConfidenceLow}
			restore := scan.SetPlatform(
				func(p string, info os.FileInfo) filesystem.Identity {
					if ino, ok := inode[p]; ok {
						return filesystem.Identity{
							ID:    model.FileIdentity{Device: 69, Inode: ino},
							Nlink: 1, Known: true, NlinkKnown: true,
						}
					}
					return filesystem.IdentityOf(p, info) // directories keep real identities
				},
				func(string) filesystem.RootInfo { return cifs },
			)
			defer restore()

			res, err := engine.Run(context.Background(), engine.Options{
				Scan: scan.Options{Roots: []string{dir}}, Mode: model.ModeExact,
			})
			if err != nil {
				t.Fatal(err)
			}

			// same_file_identity = unconfirmed, hardlink = unconfirmed
			if len(res.Files) != 2 {
				t.Fatalf("the two paths must stay separate entities, got %d files", len(res.Files))
			}
			for _, f := range res.Files {
				if f.IdentityStatus != model.IdentityUnconfirmed {
					t.Errorf("%s: identity_status = %q, want unconfirmed", f.PrimaryPath(), f.IdentityStatus)
				}
				if f.HardLinkStatus != model.HardLinkUnconfirmed {
					t.Errorf("%s: hard_link_status = %q, want unconfirmed", f.PrimaryPath(), f.HardLinkStatus)
				}
				if !f.HiddenLinksPossible {
					t.Errorf("%s: hidden_links_possible not set on CIFS", f.PrimaryPath())
				}
				wantSame := 0
				if tc.inodeA == tc.inodeB {
					wantSame = 1
				}
				if len(f.SameIdentityAs) != wantSame {
					t.Errorf("%s: same_identity_as = %v, want %d entries", f.PrimaryPath(), f.SameIdentityAs, wantSame)
				}
			}
			if res.Stats.HardlinkAliases != 0 {
				t.Errorf("hard-link aliases = %d, want 0 (not confirmed)", res.Stats.HardlinkAliases)
			}

			// deletion_safe = false, reclaimable_bytes = unknown
			for _, policy := range []string{model.PolicyConservative, model.PolicyBalanced} {
				ev, err := decision.Evaluate(res, policy)
				if err != nil {
					t.Fatal(err)
				}
				if len(ev.Groups) != 1 {
					t.Fatalf("%s: the pair must be shown for review, got %d groups", policy, len(ev.Groups))
				}
				g := ev.Groups[0]
				for _, m := range g.Members {
					if m.Decision == model.DecisionRedundantCandidate {
						t.Errorf("%s: %s proposed for deletion", policy, m.Path)
					}
				}
				if g.Action != model.ActionReview {
					t.Errorf("%s: action = %s, want REVIEW", policy, g.Action)
				}
				if g.Space.ReclaimStatus != model.ReclaimUnknown || g.Space.PotentialReclaimBytes != 0 {
					t.Errorf("%s: reclaim = %s %d bytes, want unknown", policy, g.Space.ReclaimStatus, g.Space.PotentialReclaimBytes)
				}
				plan := decision.BuildPlan(res, ev, "scan.json", model.ToolInfo{Name: model.ToolName})
				for _, pg := range plan.Groups {
					for _, a := range pg.Actions {
						if a.Type != model.PlanActionReview {
							t.Errorf("%s: plan action %s for %v, want review", policy, a.Type, a.AffectedKnownPaths)
						}
					}
				}
			}
		})
	}
}

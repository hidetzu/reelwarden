package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidetzu/reelwarden/internal/cli"
)

// These checks need no FFmpeg: they cover how mistakes on the command line
// are reported, so they never look like "no duplicates found".

func TestScanMissingRootIsPartial(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", filepath.Join(dir, "s.json"), filepath.Join(dir, "typo"))
	if code != cli.ExitPartial || !strings.Contains(errs, "root_unreadable") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestScanMissingProtectRootIsUsageError(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := run(t, "scan", "-q", "--no-cache", "--protect-root", filepath.Join(dir, "typo"), dir)
	if code != cli.ExitUsage || !strings.Contains(errs, "--protect-root") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestScanWarnsAboutIneffectiveProtectRoot(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "r", "keep"), 0o755)
	os.WriteFile(filepath.Join(dir, "r", "a.mp4"), []byte("x"), 0o644)
	code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", filepath.Join(dir, "s.json"), "--protect-root", filepath.Join(dir, "r", "keep"), filepath.Join(dir, "r"))
	// A protected root that protects nothing makes the scan partial (exit 4).
	if code != cli.ExitPartial || !strings.Contains(errs, "protect_root_unmatched") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestOutputNeverReplacesAScannedFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "r")
	os.MkdirAll(root, 0o755)
	victim := filepath.Join(root, "home.vid")
	os.WriteFile(victim, []byte("precious"), 0o644)
	os.WriteFile(filepath.Join(root, "copy.vid"), []byte("precious"), 0o644)

	// scan: the custom extension is guarded before scanning.
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "--ext", "vid", "-o", victim, root); code != cli.ExitUsage {
		t.Fatalf("scan -o onto a custom-extension file: exit %d %q", code, errs)
	}
	// Windows drops trailing dots, so "x.mp4." is still a video path.
	if code, _, _ := run(t, "scan", "-q", "--no-cache", "-o", filepath.Join(dir, "x.mp4."), root); code != cli.ExitUsage {
		t.Fatalf("trailing dot accepted: exit %d", code)
	}
	scanFile := filepath.Join(dir, "s.json")
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "--ext", "vid", "-o", scanFile, root); code != cli.ExitOK {
		t.Fatalf("scan: exit %d %q", code, errs)
	}
	// report/plan: any path recorded in the scan is refused, whatever its extension.
	other := filepath.Join(root, "notes.txt")
	os.WriteFile(other, []byte("keep"), 0o644)
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "--ext", "vid,txt", "-o", scanFile, root); code != cli.ExitOK {
		t.Fatalf("scan: exit %d %q", code, errs)
	}
	for _, cmd := range []string{"plan", "report"} {
		if code, _, _ := run(t, cmd, scanFile, "-o", other); code != cli.ExitUsage {
			t.Fatalf("%s -o onto a scanned path: exit %d", cmd, code)
		}
	}
	for p, want := range map[string]string{victim: "precious", other: "keep"} {
		if b, _ := os.ReadFile(p); string(b) != want {
			t.Fatalf("%s was modified: %q", p, b)
		}
	}
}

func TestPlanNeverReplacesItsInput(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.mp4"), []byte("same"), 0o644)
	scanFile := filepath.Join(dir, "out", "s.json")
	os.MkdirAll(filepath.Dir(scanFile), 0o755)
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", scanFile, dir); code != cli.ExitOK {
		t.Fatalf("scan: exit %d %q", code, errs)
	}
	before, _ := os.ReadFile(scanFile)
	for _, cmd := range []string{"plan", "report"} {
		if code, _, _ := run(t, cmd, scanFile, "-o", scanFile); code != cli.ExitUsage {
			t.Fatalf("%s -o <input>: exit %d", cmd, code)
		}
	}
	alias := filepath.Join(dir, "out", "alias.json")
	if err := os.Symlink(scanFile, alias); err == nil {
		if code, _, _ := run(t, "plan", alias, "-o", scanFile); code != cli.ExitUsage {
			t.Fatalf("plan <symlink to input> -o <input>: exit %d", code)
		}
	}
	if after, _ := os.ReadFile(scanFile); string(after) != string(before) {
		t.Fatal("input scan was modified")
	}
	if code, _, _ := run(t, "plan", scanFile, "-o", os.DevNull); code != cli.ExitOK {
		t.Fatalf("plan -o %s: exit %d", os.DevNull, code)
	}
}

// Hand-edited or truncated scan files are rejected with exit 1, never a panic.
func TestMalformedScanIsRejected(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "r")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "a.mp4"), []byte("same"), 0o644)
	os.WriteFile(filepath.Join(root, "b.mp4"), []byte("same"), 0o644)
	scanFile := filepath.Join(dir, "s.json")
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", scanFile, root); code != cli.ExitOK {
		t.Fatalf("scan: exit %d %q", code, errs)
	}
	raw, _ := os.ReadFile(scanFile)
	mutations := map[string]func(m map[string]any){
		"unknown member": func(m map[string]any) {
			g := m["groups"].([]any)[0].(map[string]any)
			g["members"] = append(g["members"].([]any), "f999999")
		},
		"files null": func(m map[string]any) { m["files"] = nil },
		"file null":  func(m map[string]any) { m["files"].([]any)[0] = nil },
		"duplicate ids": func(m map[string]any) {
			fs := m["files"].([]any)
			fs[1].(map[string]any)["id"] = fs[0].(map[string]any)["id"]
		},
		"no hash":      func(m map[string]any) { m["files"].([]any)[0].(map[string]any)["exact"] = nil },
		"no paths":     func(m map[string]any) { m["files"].([]any)[0].(map[string]any)["known_paths"] = nil },
		"bogus mode":   func(m map[string]any) { m["params"].(map[string]any)["mode"] = "bogus" },
		"bogus status": func(m map[string]any) { m["files"].([]any)[0].(map[string]any)["hard_link_status"] = "bogus" },
		"same identity": func(m map[string]any) {
			fs := m["files"].([]any)
			fs[1].(map[string]any)["identity"] = fs[0].(map[string]any)["identity"]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			b, _ := json.Marshal(m)
			bad := filepath.Join(t.TempDir(), "bad.json")
			os.WriteFile(bad, b, 0o644)
			for _, cmd := range []string{"plan", "report"} {
				if code, _, errs := run(t, cmd, bad); code != cli.ExitRuntime {
					t.Fatalf("%s: exit %d %q", cmd, code, errs)
				}
			}
		})
	}
}

func TestUnknownScanStatusIsRejected(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.mp4"), []byte("x"), 0o644)
	scanFile := filepath.Join(dir, "out.json")
	if code, _, errs := run(t, "scan", "-q", "--no-cache", "-o", scanFile, dir); code != cli.ExitOK {
		t.Fatalf("scan: exit %d %q", code, errs)
	}
	raw, _ := os.ReadFile(scanFile)
	bad := strings.Replace(string(raw), `"status": "complete"`, `"status": "weird"`, 1)
	os.WriteFile(scanFile, []byte(bad), 0o644)
	if code, _, _ := run(t, "plan", scanFile); code != cli.ExitRuntime {
		t.Fatalf("unknown status accepted: exit %d", code)
	}
}

func TestVersionFlag(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		code, out, _ := run(t, args...)
		if code != cli.ExitOK || !strings.HasPrefix(out, "reelwarden ") {
			t.Fatalf("%v: exit %d %q", args, code, out)
		}
	}
}

// With --ext db a cache inside the root would be scanned and rewritten.
func TestCacheInsideRootMatchingExtIsRefused(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "R")
	os.MkdirAll(filepath.Join(root, "v"), 0o755)
	os.WriteFile(filepath.Join(root, "v", "cache.db"), []byte("precious"), 0o644)
	if err := os.Symlink(filepath.Join(root, "v"), filepath.Join(dir, "via")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	for _, cacheDir := range []string{filepath.Join(root, "v"), filepath.Join(dir, "via")} {
		code, _, errs := run(t, "scan", "-q", "--ext", "db", "--cache-dir", cacheDir, "-o", filepath.Join(dir, "s.json"), root)
		if code != cli.ExitUsage {
			t.Fatalf("%s: exit %d %q", cacheDir, code, errs)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(root, "v", "cache.db")); string(b) != "precious" {
		t.Fatalf("scanned file was modified: %q", b)
	}
}

// The warning must not depend on whether the cache directory exists yet or
// is given as a relative path.
func TestCacheInsideRootIsAlwaysReported(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "R")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "a.mp4"), []byte("x"), 0o644)
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // second run: cache.db exists
		for _, c := range []string{"R", "R/", filepath.Join(dir, "R")} {
			_, _, errs := run(t, "scan", "-q", "--cache-dir", c, "-o", filepath.Join(dir, "s.json"), "R")
			if !strings.Contains(errs, "is inside scan root") {
				t.Fatalf("run %d, --cache-dir %s: no warning: %q", i, c, errs)
			}
		}
	}
}

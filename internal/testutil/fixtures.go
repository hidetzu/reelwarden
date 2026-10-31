// Package testutil generates small synthetic videos with FFmpeg for tests.
// No real or private media is ever used: every fixture comes from lavfi
// sources (testsrc2, mandelbrot, sierpinski, color, sine).
package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// FFmpeg returns the ffmpeg path or skips the test.
func FFmpeg(t testing.TB) string {
	t.Helper()
	p, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not on PATH; skipping media test")
	}
	if _, err := exec.LookPath("ffprobe"); err != nil {
		t.Skip("ffprobe not on PATH; skipping media test")
	}
	return p
}

// Gen runs ffmpeg with the given arguments (argv, no shell).
func Gen(t testing.TB, args ...string) {
	t.Helper()
	ff := FFmpeg(t)
	full := append([]string{"-hide_banner", "-nostdin", "-loglevel", "error", "-y"}, args...)
	out, err := exec.Command(ff, full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// Fixture sizes keep generation fast.
const (
	W   = 320
	H   = 180
	Dur = "12"
)

// Source returns a lavfi video source spec.
func Source(name string) string {
	switch name {
	case "testsrc2":
		return fmt.Sprintf("testsrc2=size=%dx%d:rate=25:duration=%s", W, H, Dur)
	case "mandelbrot":
		return fmt.Sprintf("mandelbrot=size=%dx%d:rate=25,trim=duration=%s", W, H, Dur)
	case "sierpinski":
		return fmt.Sprintf("sierpinski=size=%dx%d:rate=25,trim=duration=%s", W, H, Dur)
	case "black":
		return fmt.Sprintf("color=c=black:size=%dx%d:rate=25:duration=%s", W, H, Dur)
	}
	panic("unknown source " + name)
}

// Video writes a clip from a lavfi source with an optional sine audio track.
func Video(t testing.TB, path, source string, audio bool, extra ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{"-f", "lavfi", "-i", Source(source)}
	if audio {
		args = append(args, "-f", "lavfi", "-i", "sine=frequency=440:duration="+Dur, "-c:a", "aac", "-shortest")
	}
	args = append(args, "-c:v", "mpeg4", "-q:v", "3")
	args = append(args, extra...)
	args = append(args, path)
	Gen(t, args...)
}

// Transcode re-encodes src into dst with extra output options.
func Transcode(t testing.TB, src, dst string, opts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-i", src}, opts...)
	args = append(args, dst)
	Gen(t, args...)
}

// SharedIntro writes 3 seconds of testsrc2 followed by 9 seconds of main.
func SharedIntro(t testing.TB, path, main string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var mainSrc string
	switch main {
	case "mandelbrot":
		mainSrc = fmt.Sprintf("mandelbrot=size=%dx%d:rate=25", W, H)
	case "sierpinski":
		mainSrc = fmt.Sprintf("sierpinski=size=%dx%d:rate=25", W, H)
	default:
		t.Fatalf("unknown main source %q", main)
	}
	graph := fmt.Sprintf("testsrc2=size=%dx%d:rate=25:duration=3[a];%s,trim=duration=9,setpts=PTS-STARTPTS[b];[a][b]concat=n=2:v=1:a=0", W, H, mainSrc)
	Gen(t, "-f", "lavfi", "-i", graph, "-c:v", "mpeg4", "-q:v", "3", path)
}

// CopyFile copies bytes (a different physical file with identical content).
func CopyFile(t testing.TB, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// EntryState is the observable state of one directory entry.
type EntryState struct {
	Mode   string
	Size   int64
	MTime  int64
	SHA256 string
	Link   string
	Inode  string
}

// Snapshot captures hashes, link targets, modes, mtimes and identities of
// every entry under root, for read-only verification.
func Snapshot(t testing.TB, root string, identity func(string, os.FileInfo) string) map[string]EntryState {
	t.Helper()
	out := map[string]EntryState{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st := EntryState{Mode: info.Mode().String(), Size: info.Size(), MTime: info.ModTime().UnixNano()}
		if identity != nil {
			st.Inode = identity(p, info)
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			st.Link, _ = os.Readlink(p)
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			st.SHA256 = hex.EncodeToString(s[:])
		}
		out[p] = st
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// DiffSnapshots returns human-readable differences.
func DiffSnapshots(a, b map[string]EntryState) []string {
	var d []string
	for p, sa := range a {
		sb, ok := b[p]
		if !ok {
			d = append(d, "removed: "+p)
		} else if sa != sb {
			d = append(d, fmt.Sprintf("changed: %s %+v -> %+v", p, sa, sb))
		}
	}
	for p := range b {
		if _, ok := a[p]; !ok {
			d = append(d, "added: "+p)
		}
	}
	sort.Strings(d)
	return d
}

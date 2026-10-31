// Package media wraps ffprobe and ffmpeg as external processes (docs/design.md §3).
//
// Processes are always started with an argument vector (never a shell),
// with a timeout, bounded stderr capture, the file: protocol prefix on
// inputs and a protocol whitelist restricted to local files.
package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hidetzu/reelwarden/internal/model"
)

// ErrNotFound is returned when ffmpeg or ffprobe cannot be located.
var ErrNotFound = errors.New("not found")

// MaxStderr bounds the captured stderr of each subprocess.
const MaxStderr = 16 * 1024

// Stdout limits. ffprobe JSON for a normal file is tens of KiB; files with
// thousands of chapters or tags stay within a few MiB. 8 MiB per process is
// far above that and, with the default 4 media workers, bounds the worst
// case at 32 MiB, which a 512 MB NAS can afford. Frames and audio windows
// have an exact expected size and are capped at it.
const (
	MaxProbeOutput   = 8 << 20
	MaxVersionOutput = 64 << 10
)

// ErrOutputTooLarge means a process wrote more than its stdout limit; the
// output is discarded, never parsed in part.
var ErrOutputTooLarge = errors.New("output exceeds its size limit")

// DefaultTimeout bounds each subprocess invocation.
const DefaultTimeout = 60 * time.Second

// Prober returns media information for a local file.
type Prober interface {
	Probe(ctx context.Context, path string) (*model.MediaInfo, error)
	Version() string
}

// FrameExtractor returns a raw 8-bit grayscale frame of w*h bytes sampled at
// the given time. A nil slice with nil error means no frame exists there.
type FrameExtractor interface {
	ExtractRGB(ctx context.Context, path string, atSec float64, streamIndex, w, h int) ([]byte, error)
	// ExtractAudio returns AudioWindow seconds of the given audio stream from
	// atSec as signed 16-bit little-endian mono samples at AudioRate Hz.
	ExtractAudio(ctx context.Context, path string, atSec float64, streamIndex int) ([]byte, error)
	Version() string
}

// Audio window sampled at each visual sample time.
const (
	AudioRate   = 8000
	AudioWindow = 0.5
)

// Tools bundles the two binaries.
type Tools struct {
	FFmpegPath     string
	FFprobePath    string
	FFmpegVersion  string
	FFprobeVersion string
	Timeout        time.Duration
}

// Locate resolves the binaries from explicit paths or PATH and reads their
// versions. Errors wrap ErrNotFound when a binary is missing.
func Locate(ctx context.Context, ffmpegPath, ffprobePath string) (*Tools, error) {
	t := &Tools{Timeout: DefaultTimeout}
	var err error
	if t.FFprobePath, err = resolve(ffprobePath, "ffprobe"); err != nil {
		return nil, err
	}
	if t.FFmpegPath, err = resolve(ffmpegPath, "ffmpeg"); err != nil {
		return nil, err
	}
	if t.FFprobeVersion, err = readVersion(ctx, t.FFprobePath); err != nil {
		return nil, fmt.Errorf("ffprobe at %s is not usable: %w", t.FFprobePath, err)
	}
	if t.FFmpegVersion, err = readVersion(ctx, t.FFmpegPath); err != nil {
		return nil, fmt.Errorf("ffmpeg at %s is not usable: %w", t.FFmpegPath, err)
	}
	return t, nil
}

func resolve(explicit, name string) (string, error) {
	if explicit != "" {
		p, err := exec.LookPath(explicit)
		if err != nil {
			return "", fmt.Errorf("%s %q: %w", name, explicit, ErrNotFound)
		}
		return p, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s on PATH: %w", name, ErrNotFound)
	}
	return p, nil
}

var versionRE = regexp.MustCompile(`(?m)^ff(?:mpeg|probe) version (\S+)`)

func readVersion(ctx context.Context, bin string) (string, error) {
	out, _, err := run(ctx, 10*time.Second, MaxVersionOutput, bin, "-hide_banner", "-version")
	if err != nil {
		// -hide_banner makes some builds omit the first line; retry without.
		out, _, err = run(ctx, 10*time.Second, MaxVersionOutput, bin, "-version")
		if err != nil {
			return "", err
		}
	}
	if m := versionRE.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	out, _, err = run(ctx, 10*time.Second, MaxVersionOutput, bin, "-version")
	if err != nil {
		return "", err
	}
	if m := versionRE.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	return "unknown", nil
}

// Version returns a combined version string.
func (t *Tools) Version() string { return t.FFmpegVersion }

// inputURL forces the file protocol so that names like "http:..." or
// "concat:..." are never interpreted as protocols.
func inputURL(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return "file:" + abs, nil
}

// boundedBuffer keeps at most max bytes.
type boundedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	if room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.truncated = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	s := strings.TrimSpace(b.buf.String())
	if b.truncated {
		s += " [stderr truncated]"
	}
	return s
}

// run executes bin with args, capturing stdout fully and stderr bounded.
// limitedBuffer keeps at most max bytes and fails the write beyond that,
// which stops the copy from the process and lets run kill it.
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.overflow = true
		return 0, ErrOutputTooLarge
	}
	return b.buf.Write(p)
}

func run(ctx context.Context, timeout time.Duration, maxOut int, bin string, args ...string) ([]byte, string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	stdout := &limitedBuffer{max: maxOut}
	stderr := &boundedBuffer{max: MaxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if stdout.overflow {
		return nil, stderr.String(), fmt.Errorf("%s: %w (%d bytes)", filepath.Base(bin), ErrOutputTooLarge, maxOut)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, stderr.String(), ctx.Err()
		}
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return nil, stderr.String(), fmt.Errorf("%s timed out after %s", filepath.Base(bin), timeout)
		}
		msg := stderr.String()
		if msg == "" {
			msg = err.Error()
		}
		return stdout.buf.Bytes(), msg, fmt.Errorf("%s failed: %s", filepath.Base(bin), firstLine(msg))
	}
	return stdout.buf.Bytes(), stderr.String(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// ProbeVersion returns the ffprobe version string.
func (t *Tools) ProbeVersion() string { return t.FFprobeVersion }

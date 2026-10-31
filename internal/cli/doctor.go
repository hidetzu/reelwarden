package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/hidetzu/reelwarden/internal/cache"
	"github.com/hidetzu/reelwarden/internal/media"
	"github.com/hidetzu/reelwarden/internal/version"
)

func newDoctorCmd(streams IO) *cobra.Command {
	var ffmpeg, ffprobe string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check FFmpeg/FFprobe, cache location and platform support",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(cmd.Context(), streams, ffmpeg, ffprobe)
		},
	}
	cmd.Flags().StringVar(&ffmpeg, "ffmpeg-path", "", "ffmpeg binary (default: from PATH)")
	cmd.Flags().StringVar(&ffprobe, "ffprobe-path", "", "ffprobe binary (default: from PATH)")
	return cmd
}

func runDoctor(ctx context.Context, streams IO, ffmpeg, ffprobe string) error {
	out := streams.Out
	i := version.Info()
	fmt.Fprintf(out, "reelwarden %s (%s/%s, %s)\n", i.Version, i.GoOS, i.GoArch, runtime.Version())
	fmt.Fprintln(out, "exact mode: available (no external dependencies)")
	if d, err := cache.DefaultDir(); err == nil {
		fmt.Fprintf(out, "cache dir: %s\n", d)
	} else {
		fmt.Fprintf(out, "cache dir: unavailable (%v); use --cache-dir or --no-cache\n", err)
	}
	tools, err := media.Locate(ctx, ffmpeg, ffprobe)
	if err != nil {
		fmt.Fprintf(out, "video mode: UNAVAILABLE: %v\n", err)
		if errors.Is(err, media.ErrNotFound) {
			fmt.Fprintln(out, "  install FFmpeg (https://ffmpeg.org/download.html) or pass --ffmpeg-path/--ffprobe-path")
		}
		return &ExitError{Code: ExitDependency}
	}
	fmt.Fprintf(out, "ffprobe: %s (version %s)\n", tools.FFprobePath, tools.FFprobeVersion)
	fmt.Fprintf(out, "ffmpeg:  %s (version %s)\n", tools.FFmpegPath, tools.FFmpegVersion)
	if err := selfTest(ctx, tools); err != nil {
		fmt.Fprintf(out, "self-test: FAILED: %v\n", err)
		return &ExitError{Code: ExitDependency}
	}
	fmt.Fprintln(out, "self-test: ok (generated a clip, probed it and extracted a grayscale frame)")
	fmt.Fprintln(out, "video mode: available")
	fmt.Fprintln(out, "reelwarden does not bundle or redistribute FFmpeg; see https://ffmpeg.org/legal.html")
	return nil
}

// selfTest generates a 2-second clip with lavfi, probes it and extracts a
// frame. It writes only inside a fresh temporary directory.
func selfTest(ctx context.Context, t *media.Tools) error {
	dir, err := os.MkdirTemp("", "reelwarden-doctor-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	clip := filepath.Join(dir, "self test.mkv")
	gen := exec.CommandContext(ctx, t.FFmpegPath, "-hide_banner", "-nostdin", "-loglevel", "error",
		"-f", "lavfi", "-i", "testsrc2=size=160x90:rate=10:duration=2", "-c:v", "mpeg4", "-y", clip)
	if b, err := gen.CombinedOutput(); err != nil {
		return fmt.Errorf("generate test clip (lavfi + mpeg4 encoder): %w: %s", err, string(b))
	}
	mi, err := t.Probe(ctx, clip)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	v := mi.PrimaryVideo()
	if v == nil || !mi.DurationKnown {
		return errors.New("probe returned no video stream or duration")
	}
	px, err := t.ExtractRGB(ctx, clip, 1.0, v.Index, 9, 8)
	if err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	if len(px) != 9*8*3 {
		return fmt.Errorf("extract returned %d bytes", len(px))
	}
	return nil
}

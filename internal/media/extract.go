package media

import (
	"context"
	"fmt"
	"strconv"
)

// ExtractRGB decodes one frame at atSec from the given video stream,
// scaled to w x h with area averaging, as packed 8-bit RGB (w*h*3 bytes).
func (t *Tools) ExtractRGB(ctx context.Context, path string, atSec float64, streamIndex, w, h int) ([]byte, error) {
	in, err := inputURL(path)
	if err != nil {
		return nil, err
	}
	out, _, err := run(ctx, t.Timeout, w*h*3, t.FFmpegPath,
		"-hide_banner", "-nostdin", "-loglevel", "error",
		"-protocol_whitelist", "file,pipe",
		"-ss", strconv.FormatFloat(atSec, 'f', 3, 64),
		"-i", in,
		"-map", "0:"+strconv.Itoa(streamIndex),
		"-frames:v", "1",
		"-an", "-sn", "-dn",
		"-vf", fmt.Sprintf("scale=%d:%d:flags=area,format=rgb24", w, h),
		"-f", "rawvideo", "-pix_fmt", "rgb24",
		"pipe:1")
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if len(out) != w*h*3 {
		return nil, fmt.Errorf("unexpected frame size %d, want %d", len(out), w*h*3)
	}
	return out, nil
}

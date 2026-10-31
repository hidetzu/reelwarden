// Package fingerprint computes exact (SHA-256) and visual (sampled dHash)
// signatures of files. Everything streams; no file is read fully into
// memory.
package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// DefaultPartialChunk is the size of each of the three regions hashed by
// PartialHash.
const DefaultPartialChunk int64 = 64 * 1024

// ExactAlgorithmVersion is bumped when hashing semantics change.
const ExactAlgorithmVersion = 1

const bufSize = 1 << 20

// PartialHash hashes the first, middle and last chunk bytes of the file.
// Files not larger than 3*chunk are hashed fully, in which case full is
// true and the digest equals FullHash.
func PartialHash(ctx context.Context, path string, size int64, chunk int64) (digest string, full bool, err error) {
	if chunk <= 0 {
		chunk = DefaultPartialChunk
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	h := sha256.New()
	if size <= 3*chunk {
		if err := copyCtx(ctx, h, f); err != nil {
			return "", false, err
		}
		return hex.EncodeToString(h.Sum(nil)), true, nil
	}
	offsets := []int64{0, size/2 - chunk/2, size - chunk}
	buf := make([]byte, chunk)
	for _, off := range offsets {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		n, err := f.ReadAt(buf, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", false, err
		}
		h.Write(buf[:n])
	}
	return hex.EncodeToString(h.Sum(nil)), false, nil
}

// FullHash streams the whole file through SHA-256.
func FullHash(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if err := copyCtx(ctx, h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyCtx(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, bufSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

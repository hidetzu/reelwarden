package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPartialAndFullHash(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("abcdefgh"), 100_000) // 800 KiB
	big2 := append([]byte(nil), big...)
	big2[len(big2)/3] ^= 0xff // differs only in a region partial hash does not read
	small := []byte("small content")
	p1 := filepath.Join(dir, "big1")
	p2 := filepath.Join(dir, "big2")
	p3 := filepath.Join(dir, "small")
	for p, d := range map[string][]byte{p1: big, p2: big2, p3: small} {
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	ph1, full1, err := PartialHash(ctx, p1, int64(len(big)), DefaultPartialChunk)
	if err != nil || full1 {
		t.Fatalf("partial big1: %v full=%v", err, full1)
	}
	ph2, _, _ := PartialHash(ctx, p2, int64(len(big2)), DefaultPartialChunk)
	if ph1 != ph2 {
		t.Fatalf("partial hashes should collide for files differing outside sampled regions")
	}
	fh1, _ := FullHash(ctx, p1)
	fh2, _ := FullHash(ctx, p2)
	if fh1 == fh2 {
		t.Fatalf("full hashes must differ")
	}
	sum := sha256.Sum256(big)
	if fh1 != hex.EncodeToString(sum[:]) {
		t.Errorf("full hash mismatch with crypto/sha256")
	}
	ph3, full3, _ := PartialHash(ctx, p3, int64(len(small)), DefaultPartialChunk)
	fh3, _ := FullHash(ctx, p3)
	if !full3 || ph3 != fh3 {
		t.Errorf("small file partial should equal full: %v %s %s", full3, ph3, fh3)
	}
}

func TestFullHashCancellation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FullHash(ctx, p); err == nil {
		t.Error("expected cancellation error")
	}
}

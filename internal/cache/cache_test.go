package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type payload struct {
	Hash string `json:"hash"`
}

func TestCacheHitAndInvalidation(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	v := Validator{Size: 10, MTime: now, AlgorithmVersion: 1, Params: "samples=16"}
	if err := s.Put(BucketExact, "k", v, "/p", payload{Hash: "abc"}); err != nil {
		t.Fatal(err)
	}
	var out payload
	if ok, _ := s.Get(BucketExact, "k", v, &out); !ok || out.Hash != "abc" {
		t.Fatalf("expected hit, got ok=%v out=%+v", ok, out)
	}
	cases := map[string]Validator{
		"size":    {Size: 11, MTime: now, AlgorithmVersion: 1, Params: "samples=16"},
		"mtime":   {Size: 10, MTime: now.Add(time.Second), AlgorithmVersion: 1, Params: "samples=16"},
		"algo":    {Size: 10, MTime: now, AlgorithmVersion: 2, Params: "samples=16"},
		"params":  {Size: 10, MTime: now, AlgorithmVersion: 1, Params: "samples=24"},
		"missing": v,
	}
	for name, cv := range cases {
		key := "k"
		if name == "missing" {
			key = "other"
		}
		var o payload
		if ok, _ := s.Get(BucketExact, key, cv, &o); ok {
			t.Errorf("%s: expected miss", name)
		}
	}
}

func TestCacheLockedByAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := Open(dir); err == nil {
		t.Error("second open should fail while locked")
	}
}

func TestDisabled(t *testing.T) {
	d := Disabled()
	var o payload
	if ok, _ := d.Get(BucketExact, "k", Validator{}, &o); ok || d.Enabled() {
		t.Error("disabled store must miss")
	}
}

// bbolt panics on some corrupted pages; the cache must turn that into an
// error or a miss, never crash the scan.
func TestCorruptedCacheDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v := Validator{Size: 1, MTime: time.Unix(1, 0), AlgorithmVersion: 1}
	for i := 0; i < 200; i++ {
		s.Put(BucketExact, fmt.Sprintf("key-%04d", i), v, "/p", payload{Hash: strings.Repeat("x", 100)})
	}
	s.Close()
	db := filepath.Join(dir, "cache.db")
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []int{4096, 8192} {
		c := append([]byte(nil), b...)
		for i := start; i < len(c) && i < start+4096; i += 13 {
			c[i] ^= 0xA5
		}
		if err := os.WriteFile(db, c, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir)
		if err != nil {
			continue // reported as an error: fine
		}
		var out payload
		for i := 0; i < 200; i++ {
			s.Get(BucketExact, fmt.Sprintf("key-%04d", i), v, &out)
		}
		s.Put(BucketExact, "new", v, "/p", payload{})
		s.Close()
	}
}

func TestCacheRefusesNonRegularDatabase(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "scanned.mp4")
	os.WriteFile(victim, nil, 0o644)
	if err := os.Symlink(victim, filepath.Join(dir, "cache.db")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a symlinked cache.db must be refused")
	}
	os.Remove(filepath.Join(dir, "cache.db"))
	if err := os.Link(victim, filepath.Join(dir, "cache.db")); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a hard-linked cache.db must be refused")
	}
	if fi, _ := os.Stat(victim); fi.Size() != 0 {
		t.Fatal("symlink target was written")
	}
}

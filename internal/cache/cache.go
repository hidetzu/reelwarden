// Package cache stores expensive per-file results (exact hashes, media
// info, visual fingerprints) keyed by file identity, validated by size,
// mtime, ctime, algorithm version and parameters (docs/design.md §8).
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"

	"github.com/hidetzu/reelwarden/internal/filesystem"
)

// Bucket names.
const (
	BucketExact  = "exact"
	BucketMedia  = "media"
	BucketVisual = "visual"
)

// Entry is the stored envelope around a payload.
type Entry struct {
	Path             string          `json:"path"`
	Size             int64           `json:"size"`
	MTimeUnixNano    int64           `json:"mtime_unix_nano"`
	CTimeUnixNano    int64           `json:"ctime_unix_nano,omitempty"`
	AlgorithmVersion int             `json:"algorithm_version"`
	Params           string          `json:"params,omitempty"`
	ToolVersion      string          `json:"tool_version,omitempty"`
	StoredAt         time.Time       `json:"stored_at"`
	Payload          json.RawMessage `json:"payload"`
}

// Validator describes what an entry must match to be a hit.
type Validator struct {
	Size             int64
	MTime            time.Time
	CTimeUnixNano    int64 // inode change time; 0 when the platform has none
	AlgorithmVersion int
	Params           string
	ToolVersion      string // compared only if non-empty
}

func (v Validator) matches(e *Entry) bool {
	if e.Size != v.Size || e.MTimeUnixNano != v.MTime.UnixNano() || e.CTimeUnixNano != v.CTimeUnixNano || e.AlgorithmVersion != v.AlgorithmVersion || e.Params != v.Params {
		return false
	}
	if v.ToolVersion != "" && e.ToolVersion != v.ToolVersion {
		return false
	}
	return true
}

// Store is the cache interface used by the pipeline.
type Store interface {
	// Get decodes the payload into out when a valid entry exists.
	Get(bucket, key string, v Validator, out any) (bool, error)
	// Put stores the payload.
	Put(bucket, key string, v Validator, path string, payload any) error
	Close() error
	Enabled() bool
	Location() string
}

// Open opens (or creates) the cache database under dir.
func Open(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	path := filepath.Join(dir, "cache.db")
	if fi, err := os.Lstat(path); err == nil {
		// A bind mount over cache.db could make bbolt write into a scanned
		// file; refuse mount points as well as links.
		abs, _ := filepath.Abs(path)
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real // the cache directory may be reached through a link
		}
		if _, mounted := filesystem.MountPoints()[abs]; mounted {
			return nil, fmt.Errorf("cache %s is a mount point; refusing to use it (use --cache-dir or --no-cache)", path)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("cache %s is not a regular file; refusing to use it (use --cache-dir or --no-cache)", path)
		}
		// A hard link could make the cache share its data with a scanned file.
		if id := filesystem.IdentityOf(path, fi); id.NlinkKnown && id.Nlink > 1 {
			return nil, fmt.Errorf("cache %s has %d hard links; refusing to use it (use --cache-dir or --no-cache)", path, id.Nlink)
		}
	}
	return openBolt(path)
}

// openBolt opens the database, turning bbolt's panics on corrupted pages
// into an error.
func openBolt(path string) (s Store, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("cache %s is corrupted (%v); delete it or use --no-cache", path, r)
		}
	}()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		if errors.Is(err, berrors.ErrTimeout) {
			return nil, fmt.Errorf("cache %s is locked by another reelwarden process (use --cache-dir or --no-cache)", path)
		}
		return nil, fmt.Errorf("open cache %s: %w (delete it, or use --cache-dir or --no-cache)", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{BucketExact, BucketMedia, BucketVisual} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialise cache: %w", err)
	}
	return &boltStore{db: db, path: path}, nil
}

// DefaultDir returns the per-user cache directory.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "reelwarden"), nil
}

type boltStore struct {
	db     *bolt.DB
	path   string
	broken atomic.Bool
}

func (s *boltStore) Enabled() bool    { return true }
func (s *boltStore) Location() string { return s.path }
func (s *boltStore) Close() (err error) {
	defer s.guard(&err)
	return s.db.Close()
}

// guard converts a bbolt panic (corrupted page) into an error. After the
// first one the store stops touching the database for the rest of the run.
func (s *boltStore) guard(err *error) {
	if r := recover(); r != nil {
		s.broken.Store(true)
		*err = fmt.Errorf("cache %s is corrupted: %v", s.path, r)
	}
}

func (s *boltStore) Get(bucket, key string, v Validator, out any) (hit bool, err error) {
	if s.broken.Load() {
		return false, nil
	}
	defer s.guard(&err)
	var raw []byte
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		if val := b.Get([]byte(key)); val != nil {
			raw = append([]byte(nil), val...)
		}
		return nil
	})
	if err != nil || raw == nil {
		return false, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return false, nil // corrupt entry: treat as miss
	}
	if !v.matches(&e) {
		return false, nil
	}
	if err := json.Unmarshal(e.Payload, out); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *boltStore) Put(bucket, key string, v Validator, path string, payload any) (err error) {
	if s.broken.Load() {
		return nil
	}
	defer s.guard(&err)
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e := Entry{
		Path: path, Size: v.Size, MTimeUnixNano: v.MTime.UnixNano(), CTimeUnixNano: v.CTimeUnixNano,
		AlgorithmVersion: v.AlgorithmVersion, Params: v.Params, ToolVersion: v.ToolVersion,
		StoredAt: time.Now().UTC(), Payload: raw,
	}
	enc, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Put([]byte(key), enc)
	})
}

// Disabled returns a Store that never hits.
func Disabled() Store { return disabled{} }

type disabled struct{}

func (disabled) Get(string, string, Validator, any) (bool, error) { return false, nil }
func (disabled) Put(string, string, Validator, string, any) error { return nil }
func (disabled) Close() error                                     { return nil }
func (disabled) Enabled() bool                                    { return false }
func (disabled) Location() string                                 { return "" }

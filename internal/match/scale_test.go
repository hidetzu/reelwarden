package match

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/hidetzu/reelwarden/internal/model"
)

// identicalFiles returns n distinct physical files that all share one
// SHA-256, as when one video was copied n times.
func identicalFiles(n int) []model.PhysicalFile {
	files := make([]model.PhysicalFile, n)
	for i := range files {
		files[i] = model.PhysicalFile{
			ID: fmt.Sprintf("f%06d", i+1), IdentityStatus: model.IdentityKnown,
			Size: 1 << 20, Exact: &model.ExactFingerprint{SHA256: "ab" + fmt.Sprint(0) + "cdef0123456789abcdef0123456789"},
		}
	}
	return files
}

func BenchmarkBuildIdentical(b *testing.B) {
	for _, n := range []int{100, 1000, 3000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			files := identicalFiles(n)
			b.ReportAllocs()
			var edges int
			for i := 0; i < b.N; i++ {
				edges = len(Build(files, DefaultParams(), false).Edges)
			}
			b.ReportMetric(float64(edges), "edges")
		})
	}
}

// Edges and memory must grow linearly with the number of identical copies.
func TestIdenticalCopiesScaleLinearly(t *testing.T) {
	for _, n := range []int{1000, 10000} {
		files := identicalFiles(n)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		r := Build(files, DefaultParams(), false)
		runtime.ReadMemStats(&after)
		if len(r.Edges) > n {
			t.Fatalf("%d identical files produced %d edges; want at most %d", n, len(r.Edges), n)
		}
		if len(r.Groups) != 1 || len(r.Groups[0].Members) != n {
			t.Fatalf("%d identical files: %d groups", n, len(r.Groups))
		}
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > uint64(n)*4096 {
			t.Fatalf("%d identical files allocated %d bytes (> 4 KiB per file)", n, alloc)
		}
	}
}

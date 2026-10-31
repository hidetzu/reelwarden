package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkWalkManyLinks walks n files, each with one symlink pointing at it.
func BenchmarkWalkManyLinks(b *testing.B) {
	for _, n := range []int{1000, 4000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			dir := b.TempDir()
			os.MkdirAll(filepath.Join(dir, "v"), 0o755)
			os.MkdirAll(filepath.Join(dir, "l"), 0o755)
			for i := 0; i < n; i++ {
				p := filepath.Join(dir, "v", fmt.Sprintf("%05d.mp4", i))
				os.WriteFile(p, []byte{byte(i)}, 0o644)
				if err := os.Symlink(p, filepath.Join(dir, "l", fmt.Sprintf("%05d.mp4", i))); err != nil {
					b.Skip(err)
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				inv, err := Walk(context.Background(), Options{Roots: []string{dir}})
				if err != nil || len(inv.Files) != n {
					b.Fatalf("%v, %d files", err, len(inv.Files))
				}
			}
		})
	}
}

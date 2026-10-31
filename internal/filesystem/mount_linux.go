//go:build linux

package filesystem

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MountSource returns where path lives inside the filesystem that holds it,
// from /proc/self/mountinfo: for a bind mount of /vol/#recycle on /mnt/m,
// MountSource("/mnt/m/a") is "/#recycle/a" (relative to the source
// filesystem's root). It returns "" when unknown.
func MountSource(path string) string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	best, bestRoot := "", ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		root, mnt := sourceRoot(fields), unescapeMount(fields[4])
		if !under(path, mnt) || len(mnt) < len(best) {
			continue
		}
		best, bestRoot = mnt, root
	}
	if best == "" {
		return ""
	}
	rel, err := filepath.Rel(best, path)
	if err != nil {
		return ""
	}
	return filepath.Join(bestRoot, rel)
}

func under(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

func mountPoints() map[string][]string {
	out := map[string][]string{}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return out
	}
	defer f.Close()
	type entry struct{ dev, root, mnt string }
	var all []entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 5 {
			all = append(all, entry{fields[2], sourceRoot(fields), unescapeMount(fields[4])})
		}
	}
	return equivalentPaths(all, func(e entry) (string, string, string) { return e.dev, e.root, e.mnt })
}

// equivalentPaths lists, for every mount point, where its content also
// appears: its root inside the source filesystem, and the same place under
// every other mount of that filesystem. A tmpfs mounted on /x/@Recycle and
// bind-mounted on /lib/inn has root "/" at both; only the other mount point
// reveals that the content is a recycle bin.
func equivalentPaths[E any](all []E, get func(E) (dev, root, mnt string)) map[string][]string {
	out := map[string][]string{}
	for _, e := range all {
		dev, root, mnt := get(e)
		paths := []string{root}
		for _, o := range all {
			odev, oroot, omnt := get(o)
			if odev != dev || omnt == mnt {
				continue
			}
			if rel, err := filepath.Rel(oroot, root); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
				paths = append(paths, filepath.Join(omnt, rel))
			}
		}
		out[mnt] = append(out[mnt], paths...)
	}
	return out
}

// sourceRoot returns the mount's root inside its source filesystem. A ZFS
// snapshot mounted on its own ("pool/ds@daily") has root "/"; it is reported
// under a synthetic ".zfs/snapshot" path so it is recognised as a snapshot.
func sourceRoot(fields []string) string {
	root := unescapeMount(fields[3])
	for i := 5; i+2 < len(fields); i++ {
		if fields[i] == "-" {
			if fields[i+1] == "zfs" && strings.Contains(fields[i+2], "@") {
				return filepath.Join("/.zfs/snapshot", root)
			}
			break
		}
	}
	return root
}

// unescapeMount decodes the octal escapes (\040 for space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

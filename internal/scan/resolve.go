package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// errLinkLoop reads like the OS error so link cycles are classified alike.
var errLinkLoop = errors.New("too many links")

const maxLinkHops = 40

// resolveLinks resolves path component by component, following both real
// symlinks and Minshall–French XSym files wherever they appear, including
// in the middle of the path (an XSym directory link). filepath.EvalSymlinks
// only knows real symlinks, so a path through an XSym directory link would
// otherwise look broken and its target would lose the reference.
func resolveLinks(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveFrom("", abs)
}

// resolveFrom resolves target as a link written in directory dir (already
// resolved, or "" when target is absolute). Like the kernel, ".." is applied
// to the directory reached so far, never lexically to unresolved text:
// "dl/../x" means the parent of wherever dl points, not "x".
func resolveFrom(dir, target string) (string, error) {
	cur, rest := splitLink(dir, target)
	hops := 0
	for len(rest) > 0 {
		part := rest[0]
		rest = rest[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		link, isLink := "", false
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if link, err = os.Readlink(next); err != nil {
				return "", err
			}
			isLink = true
		case fi.Mode().IsRegular():
			link, isLink = readMFSymlink(next, fi.Size())
		}
		if !isLink {
			cur = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", errLinkLoop
		}
		var more []string
		cur, more = splitLink(cur, link)
		rest = append(more, rest...)
	}
	return cur, nil
}

// splitLink returns the starting directory and the components of target,
// relative to dir unless target is absolute. No cleaning happens here.
func splitLink(dir, target string) (string, []string) {
	sep := string(filepath.Separator)
	target = filepath.FromSlash(target) // XSym targets use "/" everywhere
	if filepath.IsAbs(target) {
		vol := filepath.VolumeName(target)
		return vol + sep, strings.Split(strings.TrimPrefix(target[len(vol):], sep), sep)
	}
	return dir, strings.Split(target, sep)
}

// Package scan walks the scan roots and builds the inventory: path entries,
// symlink resolution and physical-file aggregation by identity (docs/design.md §4).
// It never reads video contents; it reads only 1067-byte candidates for
// Minshall–French symlinks (mfsymlink.go).
package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/hidetzu/reelwarden/internal/filesystem"
	"github.com/hidetzu/reelwarden/internal/model"
)

// DefaultExtensions is the default list of file extensions treated as video.
var DefaultExtensions = []string{
	".mp4", ".m4v", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".webm", ".mpg",
	".mpeg", ".m2ts", ".mts", ".ts", ".vob", ".3gp", ".ogv", ".rm", ".rmvb",
	".asf", ".divx", ".f4v", ".mxf", ".dv", ".m2v", ".qt",
}

// DefaultExcludes are NAS metadata folders (thumbnails) skipped unless
// --include-hidden is set.
var DefaultExcludes = []string{"@eaDir"}

// TrashFolders are recycle bins, snapshots, backups, version stores and
// recovery folders, by exact name (compared case-insensitively). They are
// searched only for links, never for videos, not even with --include-hidden.
// This is a second line of defence: names cannot recognise every bin, so a
// candidate is proposed only when the copy that stays is under a protected
// root the user chose (docs/design.md §9).
var TrashFolders = []string{
	// Recycle bins
	"#recycle", "@Recycle", "$RECYCLE.BIN", "RECYCLER", "Recycled", ".recycle",
	".Recycle.Bin", "RecycleBin", ".Trash", ".Trashes", "Network Trash Folder",
	"@sharebin", "files_trashbin",
	// Snapshots
	"#snapshot", "@snapshots", "@sharesnap", "@Recently-Snapshot", ".snapshot", ".snapshots",
	"~snapshot", ".zfs", "timeshift", "timeshift-btrfs", ".ckpt",
	// Backups and version stores
	"Backups.backupdb", ".MobileBackups", ".DocumentRevisions-V100", "FileHistory",
	".stversions", "_gsdata_", "files_versions", ".dropbox.cache",
	// Recovery
	"lost+found", "System Volume Information",
}

// trashPrefixes match per-user bins (.Trash-1000) and shadow copies (@GMT-...).
var trashPrefixes = []string{".trash-", "@gmt-"}

// IsTrashFolder reports whether a directory name is a known recycle bin,
// snapshot, backup, version store or recovery folder.
func IsTrashFolder(name string) bool {
	l := strings.ToLower(name)
	for _, p := range trashPrefixes {
		if strings.HasPrefix(l, p) && len(l) > len(p) {
			return true
		}
	}
	for _, t := range TrashFolders {
		if strings.EqualFold(name, t) {
			return true
		}
	}
	return false
}

// isTrashPath matches bins known by their location rather than their name:
// the freedesktop home trash (~/.local/share/Trash).
func isTrashPath(p string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.ToSlash(p)), "/.local/share/trash")
}

// InTrash reports whether path, or the source of the bind mount holding it,
// lies inside a known trash folder.
func InTrash(path string) bool {
	return inTrash(path) || inTrash(filesystem.MountSource(path))
}

// inTrash reports whether any element of path is a known trash folder.
func inTrash(path string) bool {
	if strings.Contains(strings.ToLower(filepath.ToSlash(path))+"/", "/.local/share/trash/") {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if IsTrashFolder(part) {
			return true
		}
	}
	return false
}

// Options control the walk.
type Options struct {
	Roots          []string
	ProtectRoots   []string
	Extensions     []string // lowercase, with leading dot; empty means DefaultExtensions
	Excludes       []string // glob patterns matched against base names and slash-separated relative paths
	FollowSymlinks bool
	IncludeHidden  bool
	// Progress, if set, is called periodically with the number of entries found.
	Progress func(entries int)
}

// Inventory is the result of a walk.
type Inventory struct {
	Roots          []model.ScanRoot
	ProtectedRoots []string
	Entries        []model.PathEntry
	Files          []model.PhysicalFile
	Warnings       []model.Warning
	Stats          model.ScanStats
}

// Platform hooks, replaced in tests to simulate filesystems (CIFS, overlay)
// that cannot be mounted on a test machine.
var (
	identityOf  = filesystem.IdentityOf
	inspectRoot = filesystem.InspectRoot
	mountTable  = filesystem.MountPoints
)

type walker struct {
	opts       Options
	ctx        context.Context
	roots      []rootInfo
	protect    []string
	exts       map[string]bool
	excludes   []string
	inv        *Inventory
	byIdentity map[string]int // identity key -> index in inv.Files
	visitedDir map[string]bool
	symlinkRef map[string][]string // identity key -> entry IDs of symlinks resolving to it
	protectHit map[string]bool     // protected roots that protected at least one file
	devFS      map[uint64]filesystem.RootInfo
	mounts     map[string][]string // mount point -> other places its content lives
	tainted    []string            // library places also mounted inside a bin
	// linksOnly is set while walking a hidden or excluded folder: only links
	// are recorded there.
	linksOnly    bool
	visitedLinks map[string]bool
	protectIDs   map[string]string // identity key of every file under a protected root -> that root
	reported     map[string][]int  // untrusted identity key -> indexes of files reporting it
	entrySeq     int
	fileSeq      int
}

type rootInfo struct {
	index    int
	path     string // cleaned absolute path as given
	resolved string // after EvalSymlinks
}

// Walk performs the inventory walk.
func Walk(ctx context.Context, opts Options) (*Inventory, error) {
	w := &walker{
		opts:         opts,
		ctx:          ctx,
		inv:          &Inventory{},
		byIdentity:   map[string]int{},
		visitedDir:   map[string]bool{},
		symlinkRef:   map[string][]string{},
		protectHit:   map[string]bool{},
		devFS:        map[uint64]filesystem.RootInfo{},
		mounts:       mountTable(),
		visitedLinks: map[string]bool{},
		protectIDs:   map[string]string{},
		reported:     map[string][]int{},
		exts:         map[string]bool{},
	}
	exts := opts.Extensions
	if len(exts) == 0 {
		exts = DefaultExtensions
	}
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		w.exts[e] = true
	}
	w.excludes = append(w.excludes, opts.Excludes...)
	if !opts.IncludeHidden {
		w.excludes = append(w.excludes, DefaultExcludes...)
	}
	for _, p := range opts.ProtectRoots {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("protect root %q: %w", p, err)
		}
		res, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("protect root %q: %w", p, err)
		}
		if st, err := os.Stat(res); err != nil {
			return nil, fmt.Errorf("protect root %q: %w", p, err)
		} else if !st.IsDir() {
			return nil, fmt.Errorf("protect root %q: not a directory", p)
		}
		if InTrash(res) {
			return nil, fmt.Errorf("protect root %q is inside a recycle bin, snapshot or backup folder", p)
		}
		w.protect = append(w.protect, filepath.Clean(res))
		w.inv.ProtectedRoots = append(w.inv.ProtectedRoots, abs)
	}
	if err := w.prepareRoots(); err != nil {
		return nil, err
	}
	w.tainted = taintedPaths(w.mounts)
	w.collectProtected()
	for _, r := range w.roots {
		if r.resolved == "" {
			continue
		}
		if err := w.ctx.Err(); err != nil {
			return w.inv, err
		}
		w.walkDir(r.path, r, 0)
	}
	w.attachSymlinkRefs()
	w.linkReportedIdentities()
	w.checkNormalization()
	w.matchUnresolvedLinks()
	// A protected root that protects nothing is almost always a mistake
	// (typo, other case or Unicode form, wrong mount); the scan is partial.
	for i, p := range w.inv.ProtectedRoots {
		if !w.protectHit[p] {
			if _, inside := w.insideRoots(w.protect[i]); inside {
				w.warn("protect_root_unmatched", p, "no scanned file is inside this protected root")
			} else {
				w.warn("protect_root_outside_roots", p, "protected root is not inside any scan root; it protects nothing")
			}
			w.inv.Stats.Failures++
		}
	}
	w.finish()
	return w.inv, w.ctx.Err()
}

func (w *walker) prepareRoots() error {
	if len(w.opts.Roots) == 0 {
		return errors.New("at least one root is required")
	}
	seen := map[string]int{}
	for i, p := range w.opts.Roots {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("root %q: %w", p, err)
		}
		abs = filepath.Clean(abs)
		sr := model.ScanRoot{Index: i, Path: abs, IdentityConfidence: model.ConfidenceUnknown}
		ri := rootInfo{index: i, path: abs}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			sr.Error = "cannot resolve root: " + err.Error()
			w.warn("root_unreadable", abs, sr.Error)
			w.inv.Stats.Failures++
		} else if st, err := os.Stat(resolved); err != nil {
			sr.Error = "cannot stat root: " + err.Error()
			w.warn("root_unreadable", abs, sr.Error)
			w.inv.Stats.Failures++
		} else if !st.IsDir() {
			sr.Error = "root is not a directory"
			w.warn("root_not_directory", abs, sr.Error)
			w.inv.Stats.Failures++
		} else if InTrash(resolved) {
			sr.Error = "root is inside a recycle bin or snapshot folder, skipped"
			w.warn("root_in_trash", abs, sr.Error)
			w.inv.Stats.Failures++
		} else if prev, dup := seen[resolved]; dup {
			sr.Error = fmt.Sprintf("duplicate of root #%d, skipped", prev)
			w.warn("root_duplicate", abs, sr.Error)
		} else {
			ri.resolved = resolved
			fsinfo := inspectRoot(resolved)
			sr.Filesystem = fsinfo.Filesystem
			sr.NetworkFilesystem = fsinfo.Network
			sr.IdentityConfidence = fsinfo.Confidence
			if fsinfo.Network {
				w.warn("root_network_filesystem", abs, "root is on a network filesystem ("+fsinfo.Filesystem+"); file identity and link counts may be unreliable")
			}
			seen[resolved] = i
		}
		w.roots = append(w.roots, ri)
		w.inv.Roots = append(w.inv.Roots, sr)
	}
	// Nested roots: the inner one is reached through the outer; skip it.
	for i := range w.roots {
		if w.roots[i].resolved == "" {
			continue
		}
		for j := range w.roots {
			if i == j || w.roots[j].resolved == "" {
				continue
			}
			if isUnder(w.roots[i].resolved, w.roots[j].resolved) {
				msg := fmt.Sprintf("nested inside root #%d, skipped", j)
				w.inv.Roots[i].Error = msg
				w.warn("root_nested", w.roots[i].path, msg)
				w.roots[i].resolved = ""
				break
			}
		}
	}
	return nil
}

// isUnder reports whether p is equal to or inside dir.
func isUnder(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func (w *walker) insideRoots(resolved string) (rootInfo, bool) {
	for _, r := range w.roots {
		if r.resolved != "" && isUnder(resolved, r.resolved) {
			return r, true
		}
	}
	return rootInfo{}, false
}

func (w *walker) warn(code, path, msg string) {
	w.inv.Warnings = append(w.inv.Warnings, model.Warning{Code: code, Path: path, Message: msg})
}

func (w *walker) excluded(name, rel string) bool {
	if !w.opts.IncludeHidden && strings.HasPrefix(name, ".") && name != "." {
		return true
	}
	rel = filepath.ToSlash(rel)
	for _, pat := range w.excludes {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// trashMount reports whether the directory at full (a walk path under root)
// is a mount point whose source is inside a trash folder: a recycle bin
// bind-mounted under an innocent name.
func (w *walker) trashMount(full string, root rootInfo) bool {
	real := full
	if root.resolved != "" && root.resolved != root.path {
		if rel, err := filepath.Rel(root.path, full); err == nil {
			real = filepath.Join(root.resolved, rel)
		}
	}
	return w.trashMountReal(real)
}

func (w *walker) trashMountReal(real string) bool {
	for _, src := range w.mounts[real] {
		if inTrash(src) {
			return true
		}
	}
	return false
}

// realInTrash resolves path and reports whether it, or any folder above it
// that is a mount point, lies in a known bin or snapshot.
func (w *walker) realInTrash(path string) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	if inTrash(real) {
		return true
	}
	for p := real; ; {
		if w.trashMountReal(p) {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

type targetKind int

const (
	targetNormal targetKind = iota
	targetExcluded
	targetTrash
)

// classifyTarget applies the trash and exclude rules to every folder on the
// way from the scan root to resolved, as if it had been reached by walking.
func (w *walker) classifyTarget(resolved string) targetKind {
	r, ok := w.insideRoots(resolved)
	if !ok {
		return targetNormal
	}
	rel, err := filepath.Rel(r.resolved, resolved)
	if err != nil || rel == "." {
		return targetNormal
	}
	kind := targetNormal
	prefix := ""
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, part)
		if IsTrashFolder(part) || w.trashMountReal(filepath.Join(r.resolved, prefix)) {
			return targetTrash
		}
		if w.nasMeta(part) || w.excluded(part, prefix) {
			kind = targetExcluded
		}
	}
	return kind
}

// nasMeta reports whether name is a NAS metadata folder (@eaDir). Like
// hidden folders it is searched only for links unless --include-hidden.
func (w *walker) nasMeta(name string) bool {
	if w.opts.IncludeHidden {
		return false
	}
	for _, d := range DefaultExcludes {
		if strings.EqualFold(name, d) {
			return true
		}
	}
	return false
}

func (w *walker) wantExt(name string) bool {
	return w.exts[strings.ToLower(filepath.Ext(name))]
}

// targetWanted reports whether the symlink at path resolves to a regular file
// with a wanted extension. Such links are recorded whatever their own name is,
// so the target is never proposed as redundant without its references.
//
// A link that cannot be resolved here (an absolute path valid only in a
// container or on another machine) is recorded too when its target names a
// video: it may still refer to a scanned file.
func (w *walker) targetWanted(path string) bool {
	if t, err := os.Readlink(path); err == nil && w.wantExt(t) {
		return true
	}
	resolved, err := resolveLinks(path)
	if err != nil || !w.wantExt(resolved) {
		return false
	}
	st, err := os.Stat(resolved)
	return err == nil && st.Mode().IsRegular()
}

const maxDepth = 256

func (w *walker) walkDir(dir string, root rootInfo, depth int) {
	if w.ctx.Err() != nil {
		return
	}
	if depth > maxDepth {
		// Links below this point cannot be checked; the scan is partial.
		w.warn("depth_exceeded", dir, "directory nesting too deep, not descended")
		w.inv.Stats.Failures++
		return
	}
	// Cycle protection by directory identity (covers followed symlinks and
	// bind mounts). Links-only walks keep their own set, so a hidden folder
	// seen for its links is still scanned fully when a followed link leads in.
	visited := w.visitedDir
	if w.linksOnly {
		visited = w.visitedLinks
	}
	if st, err := os.Stat(dir); err == nil {
		id := identityOf(dir, st)
		if id.Known {
			k := id.ID.Key()
			if visited[k] {
				if !w.linksOnly {
					w.warn("directory_cycle", dir, "directory already visited through another path, skipped")
				}
				return
			}
			visited[k] = true
		}
	}
	if !w.linksOnly {
		w.inv.Stats.DirectoriesWalked++
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if w.linksOnly {
			// Links in an excluded folder cannot be checked: say so, since a
			// reference may be missed, but it is not a scan failure.
			// A link in there may protect a scanned file; the scan is partial.
			w.warn("excluded_directory_unreadable", dir, "links inside this excluded folder could not be checked: "+err.Error())
			w.inv.Stats.Failures++
			return
		}
		w.warn("directory_unreadable", dir, err.Error())
		w.inv.Stats.Failures++
		if len(entries) == 0 {
			return
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, de := range entries {
		if w.ctx.Err() != nil {
			return
		}
		name := de.Name()
		full := filepath.Join(dir, name)
		rel, _ := filepath.Rel(root.path, full)
		typ := de.Type()
		switch {
		case typ&fs.ModeSymlink != 0:
			if !w.wantExt(name) && !w.opts.FollowSymlinks && !w.targetWanted(full) {
				continue
			}
			w.handleSymlink(full, rel, root, depth)
		case typ.IsDir():
			if IsTrashFolder(name) || isTrashPath(full) || w.trashMount(full, root) {
				// Never a source of videos (a copy there must not be the
				// keeper), but links inside it still count as references.
				if !w.linksOnly {
					w.warn("trash_folder_skipped", full, "recycle bin, snapshot or backup folder; searched for links only")
					w.linksOnly = true
					w.walkDir(full, root, depth+1)
					w.linksOnly = false
				} else {
					w.walkDir(full, root, depth+1)
				}
				continue
			}
			if w.excluded(name, rel) && !w.linksOnly {
				// Hidden and excluded folders are still searched for links
				// (never for videos), so a reference is not lost to a filter.
				w.linksOnly = true
				w.walkDir(full, root, depth+1)
				w.linksOnly = false
				continue
			}
			w.walkDir(full, root, depth+1)
		case typ.IsRegular():
			// Every file is checked for a Minshall–French link, whatever its
			// name ("Show.S01E01", ".current"): the link keeps its own name.
			// Links are recorded even when hidden or excluded, like real
			// symlinks: a reference must never be lost to a filter.
			want := w.wantExt(name)
			excl := w.linksOnly || w.excluded(name, rel)
			info, err := de.Info()
			if err != nil {
				if want && !excl {
					w.addEntryError(full, root, err)
				}
				continue
			}
			if target, ok := readMFSymlink(full, info.Size()); ok {
				w.handleMFSymlink(full, rel, root, depth, target)
				continue
			}
			if !want || excl {
				continue
			}
			// Judge the file where it really is: through a followed link the
			// walk path can hide a bin or a bind mount of one.
			if w.trashMount(full, root) || w.realInTrash(full) {
				w.warn("trash_folder_skipped", full, "file lies in a recycle bin, snapshot or a bind mount of one; not scanned")
				continue
			}
			// Through a followed link the walk spelling can hide that the file
			// really lies in an excluded or hidden folder: judge the real path
			// the same way the walk judges folders.
			if real, err := filepath.EvalSymlinks(full); err == nil && real != full &&
				(w.classifyTarget(filepath.Dir(real)) != targetNormal || w.fileExcluded(real)) {
				continue
			}
			w.handleFile(full, root, info)
		default:
			// sockets, devices, pipes: ignored
		}
		if w.opts.Progress != nil && len(w.inv.Entries)%500 == 0 {
			w.opts.Progress(len(w.inv.Entries))
		}
	}
}

func (w *walker) nextEntryID() string {
	w.entrySeq++
	return fmt.Sprintf("e%06d", w.entrySeq)
}

func (w *walker) addEntryError(full string, root rootInfo, err error) {
	w.inv.Entries = append(w.inv.Entries, model.PathEntry{
		ID: w.nextEntryID(), Path: full, RootIndex: root.index, Kind: model.KindFile,
		Errors: []string{err.Error()},
	})
	w.warn("entry_unreadable", full, err.Error())
	w.inv.Stats.Failures++
}

func (w *walker) handleFile(full string, root rootInfo, info os.FileInfo) {
	e := model.PathEntry{ID: w.nextEntryID(), Path: full, RootIndex: root.index, Kind: model.KindFile}
	ident := identityOf(full, info)
	conf, network := w.confidenceOf(full, ident, root)
	// Paths are merged into one entity only on a trusted identity. On CIFS,
	// NFS, FUSE or overlay two paths reporting the same (dev, inode) may be
	// one file or two, so each stays separate and the clash is reported.
	key := "path:" + full
	trusted := ident.Known && conf == model.ConfidenceHigh
	if trusted {
		key = ident.ID.Key()
	}
	idx, exists := w.byIdentity[key]
	if !exists {
		w.fileSeq++
		pf := model.PhysicalFile{
			ID:                  fmt.Sprintf("f%06d", w.fileSeq),
			IdentityStatus:      model.IdentityUnknown,
			IdentityConfidence:  conf,
			HiddenLinksPossible: network,
			Size:                info.Size(),
			MTime:               info.ModTime().UTC(),
			KnownPaths:          []string{},
		}
		if ident.Known {
			pf.IdentityStatus = model.IdentityKnown
			if !trusted {
				pf.IdentityStatus = model.IdentityUnconfirmed
				w.reported[ident.ID.Key()] = append(w.reported[ident.ID.Key()], len(w.inv.Files))
			}
			id := ident.ID
			pf.Identity = &id
			pf.Nlink = ident.Nlink
			pf.NlinkKnown = ident.NlinkKnown
			pf.CTimeUnixNano = ident.ChangeTime
		} else {
			pf.IdentityConfidence = model.ConfidenceUnknown
			pf.Errors = append(pf.Errors, "file identity unavailable; treated as a separate entity")
		}
		w.inv.Files = append(w.inv.Files, pf)
		idx = len(w.inv.Files) - 1
		w.byIdentity[key] = idx
	} else {
		w.inv.Stats.HardlinkAliases++
	}
	pf := &w.inv.Files[idx]
	// Protection applies to the entity: any hard-linked path inside a
	// protected root protects every path of it.
	w.markProtected(pf, full)
	pf.KnownPaths = append(pf.KnownPaths, full)
	w.checkUTF8(pf, full)
	if exists && (pf.Size != info.Size() || !pf.MTime.Equal(info.ModTime().UTC())) {
		pf.ChangedDuringScan = true
		pf.Errors = append(pf.Errors, "size or mtime differed between hard-linked paths; file changed during scan")
	}
	e.PhysicalFileID = pf.ID
	w.inv.Entries = append(w.inv.Entries, e)
}

// confidenceOf returns the identity confidence of the filesystem holding
// path, and whether it is a network filesystem. A walk can cross into another mount (overlay, FUSE, bind mounts),
// so the filesystem is inspected per device, not only at the root.
func (w *walker) confidenceOf(path string, ident filesystem.Identity, root rootInfo) (string, bool) {
	rootConf := w.inv.Roots[root.index].IdentityConfidence
	rootNet := w.inv.Roots[root.index].NetworkFilesystem
	if !ident.Known {
		return rootConf, rootNet
	}
	dev := ident.ID.Device
	info, ok := w.devFS[dev]
	if !ok {
		// Inspect the file itself, at its final path: a single file can be
		// bind-mounted from another filesystem into a trusted directory, and
		// on Windows a directory link under C:\ can lead to a UNC share.
		final := path
		if r, err := filepath.EvalSymlinks(path); err == nil {
			final = r
		}
		info = inspectRoot(final)
		w.devFS[dev] = info
		if info.Filesystem != w.inv.Roots[root.index].Filesystem || info.Confidence != rootConf {
			w.warn("mount_crossed", path, "the walk entered another filesystem ("+info.Filesystem+", identity confidence "+info.Confidence+")")
		}
	}
	// The lower of the two: a mount inside a trusted root is judged on its own.
	network := info.Network || rootNet
	if rank(info.Confidence) < rank(rootConf) {
		return info.Confidence, network
	}
	return rootConf, network
}

func rank(c string) int {
	switch c {
	case model.ConfidenceHigh:
		return 2
	case model.ConfidenceLow:
		return 1
	}
	return 0
}

// checkUTF8 flags pf when path cannot be represented exactly in JSON.
func (w *walker) checkUTF8(pf *model.PhysicalFile, path string) {
	if utf8.ValidString(path) {
		return
	}
	if !pf.PathsNotUTF8 {
		pf.PathsNotUTF8 = true
		pf.Errors = append(pf.Errors, "a path of this file is not valid UTF-8 and is shown with replacement characters")
	}
	w.warn("path_not_utf8", path, "path is not valid UTF-8; it is shown with replacement characters and the file is never proposed as redundant")
}

// taintedPaths lists the places whose content is also mounted inside a
// known bin (a library folder bind-mounted into #recycle is emptied with
// it). The first entry of each mount's list is its root inside the source
// filesystem, not an absolute path, so it is skipped.
func taintedPaths(mounts map[string][]string) []string {
	var out []string
	for mnt, eqs := range mounts {
		if !inTrash(mnt) || len(eqs) < 2 {
			continue
		}
		out = append(out, eqs[1:]...)
	}
	return out
}

// inScope reports whether p lies in a scan root or a protected root.
func (w *walker) inScope(p string) bool {
	if _, ok := w.insideRoots(p); ok {
		return true
	}
	for _, pr := range w.protect {
		if isUnder(p, pr) {
			return true
		}
	}
	return false
}

// collectProtected records the identity of every regular file under the
// protected roots before the walk, including bins, hidden folders and the
// targets of directory links. This is only a shield: files reached through
// another path (bind mount, other case or Unicode form, hard link) are never
// proposed. Over-shielding only loses candidates; trust as a keeper is
// decided separately and narrowly (markProtected, cleanLibraryPath).
func (w *walker) collectProtected() {
	visited := map[string]bool{}
	var walk func(dir, base, label string, depth int)
	walk = func(dir, base, label string, depth int) {
		if w.ctx.Err() != nil {
			return
		}
		if depth > maxDepth {
			// Deeper files are protected by path only, not by identity.
			w.warn("depth_exceeded", dir, "protected folder nesting too deep; deeper files are not recorded for identity protection")
			w.inv.Stats.Failures++
			return
		}
		st, err := os.Stat(dir)
		if err != nil {
			w.warn("protect_root_unreadable", dir, err.Error())
			w.inv.Stats.Failures++
			return
		}
		if id := identityOf(dir, st); id.Known {
			if visited[id.ID.Key()] {
				return
			}
			visited[id.ID.Key()] = true
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			w.warn("protect_root_unreadable", dir, "cannot list a protected directory; files inside it may be reached unprotected through other paths: "+err.Error())
			w.inv.Stats.Failures++
		}
		for _, de := range entries {
			full := filepath.Join(dir, de.Name())
			switch {
			case de.IsDir():
				walk(full, base, label, depth+1)
			case de.Type()&fs.ModeSymlink != 0:
				// The shield follows directory links: what the library shows
				// through a link must not be proposed either.
				// Only where the scan can see (a link to / or /etc would
				// otherwise be walked and fail).
				if real, err := resolveLinks(full); err == nil && w.inScope(real) {
					if st, err := os.Stat(real); err == nil && st.IsDir() {
						walk(real, base, label, depth+1)
					} else if err == nil && st.Mode().IsRegular() {
						if id := identityOf(real, st); id.Known {
							w.protectIDs[id.ID.Key()] = label
						}
					}
				}
			case de.Type().IsRegular():
				info, err := de.Info()
				if err != nil {
					continue
				}
				if target, ok := readMFSymlink(full, info.Size()); ok {
					if real, err := resolveFrom(dir, target); err == nil && w.inScope(real) {
						if st, err := os.Stat(real); err == nil && st.IsDir() {
							walk(real, base, label, depth+1)
							continue
						} else if err == nil && st.Mode().IsRegular() {
							if id := identityOf(real, st); id.Known {
								w.protectIDs[id.ID.Key()] = label
							}
						}
					}
				}
				if id := identityOf(full, info); id.Known {
					w.protectIDs[id.ID.Key()] = label
				}
			}
		}
	}
	for i, p := range w.protect {
		walk(p, p, w.inv.ProtectedRoots[i], 0)
	}
}

// markProtected protects pf if path (resolved) lies in a protected root or
// the file was found under one by collectProtected.
func (w *walker) markProtected(pf *model.PhysicalFile, path string) {
	// Identity: a file reached through an alias of a protected file is
	// shielded (never proposed). This over-approximates on purpose and does
	// not make the file a trusted keeper.
	if pf.Identity != nil {
		if by, ok := w.protectIDs[pf.Identity.Key()]; ok && !pf.Protected {
			pf.Protected = true
			pf.ProtectedByRoot = by
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	// Every matching root counts as used: nested or aliased protect roots
	// must not be reported as protecting nothing.
	for i, p := range w.protect {
		if !isUnder(resolved, p) {
			continue
		}
		by := w.inv.ProtectedRoots[i]
		if !pf.Protected || pf.ProtectedByRoot == "" {
			pf.Protected = true
			pf.ProtectedByRoot = by
		}
		// path was read as a video by the walk and really lies in the
		// protected root. It is trusted only if nothing between the root and
		// the file is a hidden, excluded, metadata or bin folder, also where
		// a mount point brings in such a folder from elsewhere.
		if w.cleanLibraryPath(p, resolved) {
			w.protectHit[by] = true
			pf.InProtectedLibrary = true
		}
	}
}

// cleanLibraryPath reports whether every folder from the protected root
// prot down to the file at real is one the walk scans for videos, judged by
// name and, at mount points, by every place the mounted content also lives.
func (w *walker) cleanLibraryPath(prot, real string) bool {
	rel, err := filepath.Rel(prot, filepath.Dir(real))
	if err != nil {
		return false
	}
	dir := prot
	parts := []string{""}
	if rel != "." {
		parts = append(parts, strings.Split(rel, string(filepath.Separator))...)
	}
	relPath := ""
	for i, part := range parts {
		if i > 0 {
			dir = filepath.Join(dir, part)
			relPath = filepath.Join(relPath, part)
			if IsTrashFolder(part) || w.excluded(part, relPath) {
				return false
			}
		}
		for _, src := range w.mounts[dir] {
			if inTrash(src) || w.hiddenOrExcludedPath(src) {
				return false
			}
		}
	}
	// The file itself: a single file bind-mounted from a bin, hidden or
	// excluded place, or excluded by a root-relative pattern.
	for _, src := range w.mounts[real] {
		if inTrash(src) || w.hiddenOrExcludedPath(src) {
			return false
		}
	}
	// Reverse binds: a library folder that is also mounted inside a bin
	// would be emptied with the bin.
	for _, t := range w.tainted {
		if isUnder(real, t) {
			return false
		}
	}
	return w.classifyTarget(filepath.Dir(real)) == targetNormal && !w.fileExcluded(real)
}

// fileExcluded reports whether the file at real matches an exclude pattern
// relative to the scan root that contains it.
func (w *walker) fileExcluded(real string) bool {
	r, ok := w.insideRoots(real)
	if !ok {
		return false
	}
	rel, err := filepath.Rel(r.resolved, real)
	return err == nil && w.excluded(filepath.Base(real), rel)
}

// hiddenOrExcludedPath reports whether any element of p is hidden or a NAS
// metadata folder, or whether a trailing part of p matches an exclude
// pattern (patterns are root-relative, so every suffix is tried).
func (w *walker) hiddenOrExcludedPath(p string) bool {
	var parts []string
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	for i, part := range parts {
		if w.excluded(part, strings.Join(parts[i:], "/")) {
			return true
		}
		for j := i + 1; j <= len(parts); j++ {
			if w.excluded(parts[j-1], strings.Join(parts[i:j], "/")) {
				return true
			}
		}
	}
	return false
}

func (w *walker) handleSymlink(full, rel string, root rootInfo, depth int) {
	e := model.PathEntry{ID: w.nextEntryID(), Path: full, RootIndex: root.index, Kind: model.KindSymlink}
	target, err := os.Readlink(full)
	if err != nil {
		e.SymlinkStatus = model.SymlinkUnresolved
		e.Errors = append(e.Errors, err.Error())
		w.warn("symlink_unreadable", full, err.Error())
		w.inv.Stats.Failures++ // its target, maybe a scanned file, is unknown
		w.inv.Entries = append(w.inv.Entries, e)
		return
	}
	resolved, err := resolveLinks(full)
	w.recordLink(e, full, rel, root, depth, target, resolved, err)
}

// handleMFSymlink records a Minshall–French symlink like a real one.
func (w *walker) handleMFSymlink(full, rel string, root rootInfo, depth int, target string) {
	e := model.PathEntry{ID: w.nextEntryID(), Path: full, RootIndex: root.index, Kind: model.KindSymlink, SymlinkFormat: model.SymlinkFormatMinshallFrench}
	// The XSym file's own directory is resolved first; its target is then
	// followed from there, keeping ".." physical.
	dir, err := resolveLinks(filepath.Dir(full))
	resolved := ""
	if err == nil {
		resolved, err = resolveFrom(dir, target)
	}
	w.recordLink(e, full, rel, root, depth, target, resolved, err)
}

// recordLink classifies a link (real or Minshall–French) from its target
// and resolution result, and registers it against the file it reaches.
func (w *walker) recordLink(e model.PathEntry, full, rel string, root rootInfo, depth int, target, resolved string, err error) {
	e.SymlinkTarget = target
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			e.SymlinkStatus = model.SymlinkBroken
			w.warn("symlink_broken", full, "target does not exist: "+target)
		} else if strings.Contains(strings.ToLower(err.Error()), "too many links") || errors.Is(err, syscallELOOP) {
			e.SymlinkStatus = model.SymlinkCycle
			w.warn("symlink_cycle", full, err.Error())
		} else {
			e.SymlinkStatus = model.SymlinkUnresolved
			e.Errors = append(e.Errors, err.Error())
			w.warn("symlink_unresolved", full, err.Error())
		}
		w.inv.Entries = append(w.inv.Entries, e)
		return
	}
	e.SymlinkResolved = resolved
	st, err := os.Stat(resolved)
	if err != nil {
		e.SymlinkStatus = model.SymlinkBroken
		e.Errors = append(e.Errors, err.Error())
		w.inv.Entries = append(w.inv.Entries, e)
		return
	}
	_, inside := w.insideRoots(resolved)
	if st.IsDir() {
		e.SymlinkStatus = model.SymlinkDirectory
		if !inside {
			e.SymlinkStatus = model.SymlinkOutsideRoots
			w.warn("symlink_outside_roots", full, "directory symlink points outside the scan roots: "+resolved)
		}
		w.inv.Entries = append(w.inv.Entries, e)
		if w.opts.FollowSymlinks && inside && !w.linksOnly && !w.excluded(filepath.Base(full), rel) {
			// An XSym file is not a directory; walk what it resolves to.
			dir := full
			if e.SymlinkFormat == model.SymlinkFormatMinshallFrench {
				dir = resolved
			}
			// The rules for trash and excluded folders apply to where the
			// link leads, not only to the link's own name.
			switch w.classifyTarget(resolved) {
			case targetTrash:
				w.warn("trash_folder_skipped", full, "directory link leads into a recycle bin or snapshot folder; not followed")
			case targetExcluded:
				w.linksOnly = true
				w.walkDir(dir, root, depth+1)
				w.linksOnly = false
			default:
				w.walkDir(dir, root, depth+1)
			}
		}
		return
	}
	e.SymlinkStatus = model.SymlinkOK
	if !inside {
		// Still registered by identity below: the path may be another
		// spelling of a scanned file (a bind mount of the root, another
		// letter case), and then the link refers to it.
		e.SymlinkStatus = model.SymlinkOutsideRoots
		w.warn("symlink_outside_roots", full, "symlink points outside the scan roots: "+resolved)
	}
	if st.Mode().IsRegular() {
		ident := identityOf(resolved, st)
		if ident.Known {
			w.symlinkRef[ident.ID.Key()] = append(w.symlinkRef[ident.ID.Key()], e.ID)
		} else {
			w.symlinkRef["path:"+resolved] = append(w.symlinkRef["path:"+resolved], e.ID)
		}
	}
	w.inv.Entries = append(w.inv.Entries, e)
}

func (w *walker) attachSymlinkRefs() {
	for key, entryIDs := range w.symlinkRef {
		targets := w.reported[key] // untrusted: the link may reach any of them
		if idx, ok := w.byIdentity[key]; ok {
			targets = []int{idx}
		}
		for _, idx := range targets {
			pf := &w.inv.Files[idx]
			for _, eid := range entryIDs {
				for i := range w.inv.Entries {
					if w.inv.Entries[i].ID == eid {
						if w.inv.Entries[i].PhysicalFileID == "" {
							w.inv.Entries[i].PhysicalFileID = pf.ID
						}
						pf.SymlinkRefs = append(pf.SymlinkRefs, w.inv.Entries[i].Path)
					}
				}
			}
		}
	}
}

// matchUnresolvedLinks attaches links that could not be resolved to every
// file whose name equals the link target's last element (compared case- and
// normalization-insensitively). Such a file may be what the link means on
// the machine or container that made it, so it must not be proposed.
func (w *walker) matchUnresolvedLinks() {
	// Windows and SMB ignore trailing dots and spaces in names.
	key := func(p string) string {
		return strings.ToLower(norm.NFC.String(strings.TrimRight(filepath.Base(p), ". ")))
	}
	byName := map[string][]string{}
	for _, e := range w.inv.Entries {
		if e.Kind != model.KindSymlink || e.SymlinkTarget == "" {
			continue
		}
		switch e.SymlinkStatus {
		case model.SymlinkBroken, model.SymlinkUnresolved, model.SymlinkCycle:
			// Targets may use the other platform's separator.
			t := strings.ReplaceAll(e.SymlinkTarget, "\\", "/")
			byName[key(t)] = append(byName[key(t)], e.Path)
		}
	}
	if len(byName) == 0 {
		return
	}
	for i := range w.inv.Files {
		pf := &w.inv.Files[i]
		seen := map[string]bool{}
		for _, p := range pf.KnownPaths {
			k := key(p)
			if seen[k] {
				continue
			}
			seen[k] = true
			pf.PossibleLinkRefs = append(pf.PossibleLinkRefs, byName[k]...)
		}
		sort.Strings(pf.PossibleLinkRefs)
	}
}

// checkNormalization flags paths that differ only in Unicode normalization.
// Names are never normalized for access; NFC is used only to compare.
func (w *walker) checkNormalization() {
	byNFC := map[string][]int{} // NFC form -> entry indexes
	for i, e := range w.inv.Entries {
		k := norm.NFC.String(e.Path)
		byNFC[k] = append(byNFC[k], i)
	}
	fileIdx := map[string]int{}
	for i := range w.inv.Files {
		fileIdx[w.inv.Files[i].ID] = i
	}
	keys := make([]string, 0, len(byNFC))
	for k := range byNFC {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		idxs := byNFC[k]
		distinct := map[string]bool{}
		for _, i := range idxs {
			distinct[w.inv.Entries[i].Path] = true
		}
		if len(distinct) < 2 {
			continue
		}
		for _, i := range idxs {
			e := &w.inv.Entries[i]
			w.warn("unicode_normalization_conflict", e.Path, "another path differs only in Unicode normalization (NFC/NFD); they look identical and may be one file over SMB or on macOS")
			if fi, ok := fileIdx[e.PhysicalFileID]; ok && !w.inv.Files[fi].UnicodeConflict {
				w.inv.Files[fi].UnicodeConflict = true
				w.inv.Files[fi].Errors = append(w.inv.Files[fi].Errors, "a path differs from another only in Unicode normalization")
			}
		}
	}
}

// linkReportedIdentities cross-references files that reported the same
// identity on an untrusted filesystem.
func (w *walker) linkReportedIdentities() {
	for _, idxs := range w.reported {
		if len(idxs) < 2 {
			continue
		}
		for _, i := range idxs {
			pf := &w.inv.Files[i]
			for _, j := range idxs {
				if j != i {
					pf.SameIdentityAs = append(pf.SameIdentityAs, w.inv.Files[j].ID)
				}
			}
			w.warn("identity_unconfirmed", pf.PrimaryPath(), "another path reported the same file identity on a filesystem that cannot confirm it; they may be one file or two")
		}
	}
}

func (w *walker) finish() {
	st := &w.inv.Stats
	st.EntriesFound = len(w.inv.Entries)
	for i := range w.inv.Entries {
		switch w.inv.Entries[i].Kind {
		case model.KindFile:
			st.Files++
		case model.KindSymlink:
			st.Symlinks++
		}
	}
	st.PhysicalFiles = len(w.inv.Files)
	for i := range w.inv.Files {
		pf := &w.inv.Files[i]
		sort.Strings(pf.KnownPaths)
		sort.Strings(pf.SymlinkRefs)
		st.PhysicalBytes += pf.Size
		st.LogicalBytes += pf.Size * int64(len(pf.KnownPaths))
		switch {
		case pf.IdentityStatus != model.IdentityKnown || pf.IdentityConfidence != model.ConfidenceHigh:
			pf.HardLinkStatus = model.HardLinkUnconfirmed
		case len(pf.KnownPaths) > 1 || (pf.NlinkKnown && pf.Nlink > 1):
			pf.HardLinkStatus = model.HardLinkConfirmed
		case pf.NlinkKnown:
			pf.HardLinkStatus = model.HardLinkNone
		default:
			pf.HardLinkStatus = model.HardLinkUnconfirmed
		}
		if pf.NlinkKnown && pf.Nlink > uint64(len(pf.KnownPaths)) {
			pf.UnverifiedExternalLinks = true
		}
		if pf.IdentityConfidence == model.ConfidenceLow && pf.NlinkKnown && pf.Nlink <= 1 && len(pf.KnownPaths) == 1 {
			// Network filesystems often report nlink=1 regardless; cannot verify.
			pf.UnverifiedExternalLinks = true
		}
	}
	if w.opts.Progress != nil {
		w.opts.Progress(len(w.inv.Entries))
	}
}

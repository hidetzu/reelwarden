# reelwarden design (v0.1)

The design decisions made before the first release, with the reasons. Code
comments point here as `docs/design.md §N`. If a later change overrides a
section, update the section in the same change and explain why in the PR
description.

## 1. Scope and prior art

Surveyed from each project's README on 2026-10-31:

| Project | Video similarity | Hard links / symlinks | Destructive actions | Keep decision |
|---|---|---|---|---|
| Czkawka (Rust, MIT) | Yes; algorithm not stated | Invalid-symlink tool only | Yes | Not stated |
| fclones (Rust, MIT) | No, exact hashes | Linked files not duplicates by default | `remove`/`link`/`move`/`dedupe` from a saved report | Age/name/path |
| video-duplicate-finder (Python, MIT) | 12 sampled 9x8 dHash frames | Not stated | Trash/move/delete after confirmation | Resolution, bitrate, size |
| vid-fp (Rust, MIT/Apache-2.0) | Keyframe perceptual hashes | Inode-aware, reported once | Report-only by default; delete/move opt-in | Length, resolution, bits/frame |

None lists *every* path of a hard-linked file, warns when `nlink` exceeds the
paths found, refuses to decide when tracks or HDR differ, or writes a plan
with preconditions. reelwarden differentiates on those (entity-aware
inventory, explained decisions, read-only plans), and on proposing a copy
only against a library the user declared, and does not
compete on speed or recall. Out of scope for v0.1: GUI, daemon, transcoding,
trim/crop/speed robustness, VMAF/SSIM.

## 2. Language and distribution

Go with `CGO_ENABLED=0`: one static binary for linux, darwin and windows on
amd64 and arm64, plus 32-bit ARMv7 Linux for low-end NAS (Synology DS218j:
ARMv7, 512 MB), cross-compiled from any host. Dependencies stay few and pure
Go: cobra (CLI), bbolt (cache), x/sys (system calls, Windows file identity), x/text
(Unicode normalization, used only to compare names).

## 3. FFmpeg as external processes

FFmpeg is LGPL or GPL depending on the build (https://ffmpeg.org/legal.html).
Linking it needs CGO and couples us to the build's license; bundling it makes
us a redistributor. So `ffprobe`/`ffmpeg` are run as separate programs from
`PATH` or `--ffprobe-path`/`--ffmpeg-path`, and are not shipped.

- Argument arrays only, never a shell. Per-call timeout, 16 KiB stderr cap,
  separate worker pool from file I/O.
- Inputs use the `file:` prefix and `-protocol_whitelist file`, so a file
  named `http://...` or `concat:...` is never treated as a protocol.
- `--mode exact` needs no FFmpeg; `--mode video` and `doctor` fail clearly
  without it.

Running FFmpeg as a separate program, not linking it, is the common reading
of how GPL/LGPL code can be used from an MIT tool; this is not legal advice.

## 4. Data model: paths, physical files, content

Three layers in the scan JSON:

- `PathEntry`: a directory entry (`file` or `symlink`). Symlinks record
  target, resolved path and status (`ok`, `broken`, `cycle`,
  `outside_roots`, `directory`, `unresolved`) and are never entities.
- `PhysicalFile`: one entity by (device, inode), or (volume serial, file
  index) on Windows, with all `known_paths`, `symlink_refs` and `nlink`.
- `MatchEdge`: `byte_identical`, `visually_similar`, `uncertain`
  (`partial_overlap` is reserved). Hard-link aliases appear as
  `same_file_alias` rows in CSV.

Rules: `nlink` above the paths found sets `unverified_external_links`.
Unknown identity makes each path its own entity. Files on NFS/SMB/FUSE,
overlay/aufs (or UNC/remote drives on Windows) get `identity_confidence:
low`; FAT and exFAT (unstable inode numbers on Linux, entry-based numbers
elsewhere) and unlisted filesystems get `unknown`. The filesystem is judged
at each file's final path. The filesystem is checked again
whenever the walk enters another device (`mount_crossed` warning), because
a stacked mount shows one file under a second identity. On such untrusted
filesystems paths are never merged on the reported (dev, inode): each stays
its own entity with `identity_status: unconfirmed`, `hard_link_status:
unconfirmed`, and files reporting the same identity list each other in
`same_identity_as`. Any group touching an unconfirmed identity is review
only, with reclaimable space unknown.

Network filesystems (CIFS/SMB, NFS, FUSE) can also hide links entirely: the
server resolves its own symlinks, so the client sees two regular files. With
CIFS `serverino` both paths report the server's inode (same identity,
nlink 1); with `noserverino` the client invents inode numbers, so one file
shows two identities. Neither case can be told apart from two real copies.
Files there carry `hidden_links_possible`, and a member or keeper with it is
never part of a candidate.

Links are observed with `lstat` (the entry itself) and `stat` (what it
reaches) and kept apart from content: hard links are paths of one entity,
symlinks are references to it, and neither is ever a duplicate or counted
twice in physical or reclaimable bytes. Directory symlinks are followed
only with `--follow-symlinks`, once each, and never outside the roots.
Minshall–French symlinks (1067-byte `XSym` files that SMB clients write when
the server cannot hold symlinks) are recognised in files of any name when
their format, length and MD5 checksum are valid; they are recorded as
symlinks with `symlink_format: minshall-french`.

Paths are resolved component by component through both kinds of link, with
`..` applied to the directory actually reached (as the kernel does), and a
link counts for the file whose identity it reaches, even through a path that
looks outside the roots. Hidden and excluded folders are searched for links
but never for videos; the same holds for NAS metadata folders (`@eaDir`).
XSym files are accepted as Linux `parse_mf_symlink` accepts them (first 17
hex digits of the MD5), so no link the CIFS client would follow is missed. A link
that cannot be resolved here holds every file with the target's name.

Protection follows identity, not path spelling: the identity of every file
under a protected root is recorded before the walk, so a bind mount, another
letter case or Unicode form of the protected path still protects the file.
A protected root that protects nothing makes the scan partial.

Names are never normalized for access. Paths that differ only in Unicode
normalization (NFC/NFD) look identical and may be one file over SMB or on
macOS; they are flagged `unicode_conflict` and never decided.

## 5. Exact matching

Only entities of equal size are read: partial SHA-256 (first, middle, last
64 KiB), then streaming full SHA-256. Only equal full hashes make
`byte_identical`. SHA-256 because users can verify plan preconditions with
standard tools. Each file is re-stat'ed after reading; a size or mtime
change marks it `changed_during_scan` and discards the result.

## 6. Visual fingerprint

16 frames at `(i + 0.5) / 16 * duration`, so two encodes of the same footage
sample the same moments. Each frame is scaled to 9x8 RGB; its BT.601 luma
is hashed with dHash (64 bits), and its mean Cb/Cr and mean chroma
magnitude are kept so greyscale, tinted or graded copies can be told
apart. Chroma is also averaged per cell of a 3x3 grid, so a hue rotation of
a picture whose colours average out to grey still shows (re-encodes of the
synthetic set differ by < 1.3; grading, hue shifts and greyscale by > 6;
`balanced` reviews anything above 3). Frames with luminance stddev < 6 or
mean < 8 are low-information and ignored. Sampling parameters, algorithm version and
FFmpeg version are part of the fingerprint. Keyframe hashing was rejected
because keyframe positions differ between encodes; pHash is deferred.

Not handled: trims, time offsets, crops, letterboxing, speed changes,
watermarks. Those end as no match or `uncertain`, never `visually_similar`.

## 7. Matching and grouping

Only files whose durations differ by at most max(2 s, 2%) are compared.
Per pair: comparable frames, matching frames (Hamming <= 10), mean Hamming.

- `visually_similar`: >= 8 comparable, >= 80% matching, mean <= 12.
- `uncertain`: >= 4 comparable, >= 50% matching. Shown, never grouped.

Groups are connected components over the first two relations and keep every
edge. A decision needs a direct edge to the keeper, so A~B and B~C never
make C redundant against A. Thresholds were tuned on the synthetic set in
`internal/cli/e2e_test.go` only.

## 8. Cache

bbolt (pure Go, MIT, transactional single file) over JSON (loses progress on
crash) and modernc SQLite (heavier). Keyed by entity identity, valid only if
size, mtime, ctime (Linux, macOS), algorithm version, parameters and FFmpeg
version all match. ctime cannot be set back, so a rewrite that restores mtime
still invalidates the entry. The exact cache keeps only partial hashes as a
pre-filter: a `byte_identical` edge always rests on full SHA-256 hashes read
in the same run, so a stale entry can hide a duplicate but never invent one.
Default `os.UserCacheDir()/reelwarden`; `--cache-dir`, `--no-cache`. The
cache only saves time; `--no-cache` removes the residual risk of a reused
inode with identical size and mtime.

## 9. Decisions

Values: `recommended_keep`, `redundant_candidate` (not a deletion
approval), `manual_review`, `insufficient_evidence`. Rules, in order:

1. Missing media info, a file changed during the scan, or a path that is not
   valid UTF-8 (JSON would show it with replacement characters, so two paths
   could look the same): insufficient evidence.
2. Protected files are never redundant; two protected members are both
   review. A file is protected if any of its hard-linked paths is under a
   protected root. A missing protected root is a usage error; one that
   protects nothing makes the scan partial (exit 4).
3. Byte-identical: equal quality; keeper by protection, references, age,
   path.
4. Visually similar: review if either copy has subtitles (their text is not
   compared), or if audio tracks or languages, video
   track count, data streams (telemetry, timecode), chapters, HDR/SDR or
   duration (> max(1 s, 0.5%)) differ, either copy has cover art or other
   attachments (their contents are not compared), or decoding had problems.
5. Otherwise resolution >= 1.2x wins; same resolution and codec, bitrate
   >= 1.1x wins; different codecs at the same resolution, or a winner with
   lower frame rate or bit depth, means review.
6. `conservative` (default) never proposes visually similar files.
   `balanced` (experimental) may, but only when every sampled frame matches,
   the colours match and the picture is not near-static. Audio content and anything between
   the samples are never compared, and dHash ignores small details, so a
   different soundtrack or burned-in text or logos can still slip through;
   plans say so.
7. No direct edge to the keeper: review.
8. External hard links, low-confidence identity of the member or of the
   keeper (it might be the same file seen through another mount) or
   symlinks pointing at the file: review.
9. If the keeper itself needs review, no member is a candidate.
10. The keeper must be a trusted library file: a path of it was read as a
    video by the walk and really lies under a protected root
    (`in_protected_library`). `protected` alone is broader: it is also set
    from the identity of any file under a protected root (hard links, bind
    mounts, hidden or non-video names) and only shields a file from being
    proposed. Over-shielding and under-trusting both only lose candidates.
    Names cannot tell a library
    from a recycle bin, snapshot, backup or version store in every case, so
    the user declares the copy that stays; without one, groups are review
    only (`no_protected_keeper`). A protected root inside a known bin is a
    usage error.
11. A partial or cancelled scan yields no candidates (`scan_incomplete`).

No single score. Space is reported as logical (paths), physical (entities)
and potential reclaim (candidates only), noting that reflinks, compression,
snapshots and NAS dedup change real savings.

## 10. Read-only v0.1

`scan`, `report`, `plan`, `doctor` and `version` never modify, move, relink
or set timestamps of scanned files (reading may update atime, as any
reader does); only `--output` and the cache are written. `--output` refuses
video extensions (including `--ext` ones and Windows trailing dots) and any
path recorded in the scan. `plan` writes `review` / `candidate_remove` actions with
preconditions (path, identity, size, mtime, SHA-256), affected paths and
warnings, marked non-executable. A future `apply` needs this section updated first (agreed in an issue) and must
re-verify preconditions immediately before acting, require explicit consent,
keep an audit log and handle partial failure. Tests snapshot the fixture tree
(hashes, identities, mtimes, link targets) before and after every command.

## 11. CLI and exit codes

Results to stdout or `--output` (atomic; refuses video extensions); progress
and warnings to stderr. Dot-folders and NAS metadata folders (`@eaDir`) are
searched only for links unless `--include-hidden`. Known recycle bins,
snapshots, backups, version stores and recovery folders (an exact-name list
plus `.Trash-*`, `@GMT-*` and `~/.local/share/Trash`) are searched only for
links, never for videos, also where a followed directory link leads and,
on Linux, when bind-mounted under another name (`/proc/self/mountinfo`).
A root or protected root inside one is refused, files are judged at their
real path (also through followed links). The identity pre-pass of protected
roots records everything below them, including bins, hidden folders and
directory-link targets, but only as a shield. A keeper is trusted only when
every folder from the protected root down to it would be scanned for videos,
judged by name and, at mount points, by every place the mounted content also
lives. A ZFS snapshot mounted on its own is recognised from mountinfo. This is defence in depth:
names cannot recognise every bin, so §9 rule 10 requires a protected keeper
for any candidate. The depth limit (also in protected roots) and unreadable
excluded folders make the scan partial, and a partial or cancelled scan
yields no candidates.

Exit codes: 0 success, 1 runtime error, 2 usage error, 3 missing FFmpeg,
4 partial failures (output written), 130 cancelled (partial output written).

## 12. Code layout

```
cmd/reelwarden        entry point, Ctrl-C handling
internal/cli          commands, flags, exit codes
internal/engine       pipeline, worker pools, change detection
internal/scan         walk, link semantics, protected roots
internal/filesystem   per-OS identity, nlink, network FS detection
internal/fingerprint  SHA-256, dHash
internal/media        ffprobe/ffmpeg adapters
internal/match        candidates, pair metrics, groups
internal/quality      media profiles and comparison
internal/decision     decisions and plans
internal/report       table, JSON, CSV
internal/cache        bbolt cache
internal/model        versioned JSON schema (readers reject other versions)
internal/testutil     FFmpeg-generated fixtures for tests
```

Measured so far (tmpfs, not a NAS): 5,000 paths / 4,789 files in 0.19 s cold
and 0.10 s with cache in exact mode; only the 943 same-size files were read.
Large libraries on NFS/SMB and accuracy on real collections are not measured.

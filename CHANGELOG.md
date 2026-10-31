# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Planned as `0.1.0-dev.1`, the first development preview. Read-only: nothing is deleted, moved or relinked.

### Added

- `scan` (`--mode exact` without FFmpeg, `--mode video` with it), `report`
  (table, JSON, CSV), read-only `plan`, `doctor`, `version` / `--version`.
- Paths, physical files and content kept apart: hard links are one entity
  with every path listed, symlinks (real and Minshall–French `XSym`) are
  references, and neither is counted twice in physical or reclaimable bytes.
- Exact matching (size, partial and full SHA-256) and visual matching
  (16 sampled frames: luma dHash plus colour per 3x3 cell); `uncertain`
  results are shown but never grouped.
- Explained keep/review decisions, protected roots, and the `conservative`
  (default) and experimental `balanced` policies.
- Cache (bbolt), GoReleaser configuration with builds for Linux, macOS and
  Windows (amd64, arm64) and Linux ARMv7 for low-end NAS. Tested on Linux
  (amd64, and ARMv7 on a Synology DS218j); macOS and Windows by CI only.

### Safety measures

- Protection follows file identity: a file is protected if any path of it,
  including bind mounts and other letter-case or Unicode spellings, lies in
  a protected root. A missing protected root is a usage error; one that
  protects nothing makes the scan partial (exit 4).
- `byte_identical` rests on full SHA-256 hashes read in the same run; cache
  entries are checked by size, mtime, ctime, algorithm and parameters.
- Links are resolved component by component through real symlinks and XSym
  files, with `..` applied physically, and registered by the identity of
  the file they reach. Links in hidden or excluded folders are still
  found. A file named by a link that cannot be resolved here (broken, or an
  absolute path from a container or another machine) is held for review.
- Network, FUSE, overlay and unlisted filesystems are not trusted: paths
  are never merged on their reported identity, server-side links are
  assumed possible (`hidden_links_possible`), and no candidate is proposed
  when either the member or the keeper is there. Filesystem trust is
  judged per file, also across mounts.
- Files with non-UTF-8 names or names differing only in NFC/NFD are never
  proposed.
- A candidate is proposed only when its byte-identical (or, under
  `balanced`, better) copy stays under a `--protect-root` the user chose;
  without one, duplicates are listed for review only.
- Known recycle bins, snapshots, backups and version stores are searched
  only for links, also through followed links and bind mounts (folders and
  single files, judged at the real path also through followed links).
- Protection has two parts: any file reached as an alias of a protected
  file is shielded from being proposed, but only a file the scan read as a
  video inside a protected root (`in_protected_library`) can be the keeper.
  Links in hidden folders, bins and `@eaDir` count as references. A keeper
  is trusted only through a library path free of bins, hidden, excluded
  and metadata folders, also across bind mounts in either direction. FAT and
  exFAT are not trusted for identity.
- A scan that did not finish (partial or cancelled) yields no candidates;
  the depth limit and unreadable excluded folders make a scan partial.
- `balanced` proposes a re-encode only when every sampled frame and the
  colours match, the picture is not near-static, neither copy has
  subtitles, cover art or attachments and data streams match; plans warn that audio
  is not compared.
- Missing or non-directory roots exit 4 and are reported even with
  `--quiet`.
- `--output` never replaces a scanned file or the input scan; a cache that
  would itself be scanned, or a non-regular or hard-linked `cache.db`, is
  refused.
- Corrupted caches and inconsistent scan files give errors, not panics;
  table output quotes control characters in names.
- Release archives include third-party license texts.

[Unreleased]: https://github.com/hidetzu/reelwarden/commits/main

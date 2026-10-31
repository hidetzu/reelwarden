# reelwarden

[![ci](https://img.shields.io/github/actions/workflow/status/hidetzu/reelwarden/ci.yml?branch=main&style=flat-square)](https://github.com/hidetzu/reelwarden/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/hidetzu/reelwarden.svg?style=flat-square)](LICENSE)

reelwarden finds duplicate and visually similar videos, explains which copy is worth keeping, and writes a
cleanup plan that never breaks hard links or symlinks. It is read-only: it never deletes, moves, renames or
relinks anything.

Status: `v0.1.0-dev.1`, a development preview. Design and trade-offs: [`docs/design.md`](docs/design.md).

## Features

- Paths, physical files and content kept apart: hard-linked paths are one file, never "duplicates"; symlinks
  (including SMB `XSym` links) are references; every path is listed
- Byte-identical copies found without FFmpeg; re-encodes, resolution and container changes found with FFmpeg
- A copy is proposed as redundant only when an identical copy stays in a library you declared with
  `--protect-root` — reelwarden never guesses which copy is safe to keep
- Every keep/review decision comes with reasons; differences in audio or subtitle tracks, HDR, duration or
  attachments are flagged for review, not guessed
- Safe on NAS: recycle bins, snapshots, network and untrusted filesystems, and links it cannot resolve all lead
  to review, never to a candidate
- `plan` writes candidates with preconditions and warnings; nothing is executed

## Install

```sh
go install github.com/hidetzu/reelwarden/cmd/reelwarden@latest
```

To install a specific version, name it instead of `@latest`:

```sh
go install github.com/hidetzu/reelwarden/cmd/reelwarden@v0.1.0-dev.1
```

It needs the Go version named in [`go.mod`](go.mod) or newer. Prebuilt archives for Linux, macOS and Windows
(amd64, arm64, and 32-bit ARMv7 Linux for low-end NAS such as the Synology DS218j) are attached to GitHub
Releases with SHA-256 checksums.

`--mode video` needs `ffmpeg` and `ffprobe` on `PATH` (or `--ffmpeg-path` / `--ffprobe-path`). FFmpeg is not
bundled; install it from your package manager or <https://ffmpeg.org/download.html>. `reelwarden doctor`
checks your setup.

## Usage

```sh
# Protect the library you trust; copies elsewhere can then be proposed.
reelwarden scan ./Library ./Old --protect-root ./Library -o scan.json               # byte-identical, no FFmpeg
reelwarden scan ./Library ./Old --protect-root ./Library --mode video -o scan.json  # also re-encodes

reelwarden report scan.json                  # table (or -f csv / -f json)
reelwarden plan scan.json -o plan.json       # read-only plan
```

Without `--protect-root`, duplicates are listed for review only and nothing is proposed. Files under a
protected root are never proposed themselves. Other useful options: `--exclude GLOB`, `--follow-symlinks`,
`--io-workers N` / `--media-workers N` (keep low on a slow NAS) and `--cache-dir DIR` / `--no-cache`. Run
`reelwarden <command> --help` for all of them.

Decisions are `recommended_keep`, `redundant_candidate` (a candidate, not a deletion approval),
`manual_review` and `insufficient_evidence`. `report` and `plan` default to `--policy conservative`, which
proposes only byte-identical copies. `--policy balanced` (experimental) also proposes clearly inferior
re-encodes; it compares 16 sampled frames by default and never compares audio, so check each of its
candidates yourself.

Exit codes: `0` ok, `1` error, `2` usage, `3` FFmpeg missing, `4` partial (for example a root that does not
exist; a partial scan yields no candidates), `130` cancelled. See [`docs/design.md`](docs/design.md) §11.

## Limitations

- Trimmed, time-shifted, cropped, sped-up or watermarked copies are usually not found.
- Thresholds are tuned on synthetic test videos only; no accuracy figures are claimed. Quality is compared
  from metadata, not perceptual metrics, so a higher resolution may be an upscale.
- Recycle bins and snapshots are recognised by known names (`#recycle`, `@Recycle`, `$RECYCLE.BIN`,
  `.Trash*`, `#snapshot`, `.snapshots`, `.zfs`, `@GMT-*`, ...). Names cannot recognise every bin, so do not
  protect a folder that holds one under another name.
- On NFS/SMB, FUSE, overlay, FAT/exFAT and unrecognised filesystems, file identity may be unreliable, so
  nothing there is proposed.
- Tested on Linux (amd64, and ARMv7 on a Synology DS218j). macOS and Windows are covered by CI only
  and have not been tried on real machines yet.

The full list is in [`docs/design.md`](docs/design.md).

## Security and privacy

reelwarden only reads the files you point it at; it writes only the `--output` file and its cache, and sends
nothing over the network. FFmpeg is run with `file:` inputs only. Scan, report and plan files contain absolute
paths: treat them as private. To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

MIT ([`LICENSE`](LICENSE)). Third-party license texts are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt) and ship in every release archive. FFmpeg is not
included, linked or redistributed.

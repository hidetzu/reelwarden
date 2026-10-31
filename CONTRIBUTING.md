# Contributing

- Safety first: when unsure, a change should produce `manual_review`, not
  `redundant_candidate`. Anything that deletes, moves or relinks files needs
  a design update in `docs/design.md` §10 first, agreed in an issue.
- Never commit real videos, real paths or scan outputs. Tests generate
  fixtures with FFmpeg (`internal/testutil`).
- Work on a branch, use Conventional Commits, add tests, and update
  `CHANGELOG.md`.

```bash
test -z "$(gofmt -l .)" && go vet ./... && go test ./...   # media tests skip without ffmpeg
```

## Releasing (maintainers)

After CI is green, update `CHANGELOG.md` as Keep a Changelog asks: rename
`## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` (pre-releases too, e.g.
`0.1.0-dev.1`), add a new empty `## [Unreleased]` above it, and update the
links at the bottom (`[Unreleased]: .../compare/vX.Y.Z...HEAD`,
`[X.Y.Z]: .../releases/tag/vX.Y.Z`). Then
`git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`. The Release
workflow builds archives and `checksums.txt` into a draft release; review and
publish it by hand.

# Changelog

Release tags are `vX.Y.Z`. They are immutable: a bad release is fixed with a new patch version, never by moving a tag (trueseal-sync ADR-0030).

## Unreleased

- Cargo.toml `license` is now `Apache-2.0`, matching `LICENSE`. It previously said MIT.
- The release workflow fails a tag push when the tag version differs from the `version` in Cargo.toml (`scripts/check-tag-version.sh`).
- The README describes the XX Receive Session and NK Push Session between a device and the relay, replacing a claim that XX runs between devices.
- ADR-0005 is marked superseded. The Rust crate is the only implementation, and trueseal-relay uses `github.com/flynn/noise`.

The next release is planned as 0.2.0, the first tag where the Cargo version and the tag must match.

## Tag history before 0.2.0

Cargo.toml stayed at `version = "0.1.0"` for every tag below, so the crate version does not identify these releases.

| Tag | Commit | Date |
|---|---|---|
| v0.1.0 | `c04ee2f` | 2026-05-08 |
| v0.1.1 | `c5d52f7` | 2026-05-10 |
| v0.1.2 | `d704ad2` | 2026-05-16 |
| v0.1.3 | `d704ad2` | 2026-05-16 |
| v0.1.4 | `d704ad2` | 2026-05-16 |

v0.1.2, v0.1.3 and v0.1.4 point at the same commit and contain identical code. They are left in place rather than deleted, because tags are immutable.

# Changelog

Release tags are `vX.Y.Z`. They are immutable: a bad release is fixed with a new patch version, never by moving a tag (trueseal-sync ADR-0030).

## Unreleased

- Cargo.toml `license` is now `Apache-2.0`, matching `LICENSE`. It previously said MIT.
- The release workflow fails a tag push when the tag version differs from the `version` in Cargo.toml (`scripts/check-tag-version.sh`).
- The README describes the XX Receive Session and NK Push Session between a device and the relay, replacing a claim that XX runs between devices.
- ADR-0005 is marked superseded. The Rust crate is the only implementation, and trueseal-relay uses `github.com/flynn/noise`.
- **Breaking:** XX and NK `dial`/`accept` (Rust) and `dial_xx`/`accept_xx`/`dial_nk`/`accept_nk` (UniFFI) take a `prologue` argument, which is mixed into the Noise handshake hash. Both peers must pass identical bytes or the handshake fails on both sides. The caller owns the contents, such as the Transport Version prefix (trueseal-sync ADR-0022). Pass an empty prologue to bind nothing.
- `trueseal_noise::MAX_PLAINTEXT_SIZE` (65,519 bytes) is now public. README and CONTEXT.md state the u16 frame ceiling (65,535 bytes) and the 16-byte AEAD tag it comes from (trueseal-sync ADR-0025).
- Fixed: concurrent `send` calls on one session could write frames out of nonce order, and concurrent `receive` calls could split a frame, so the peer failed to decrypt. `send` now serialises encrypt and write, and `receive` serialises read and decrypt. A `send` overlaps a pending `receive` only when the transport's `read()` returns `WouldBlock` rather than blocking (README Limits, CONTEXT.md Concurrency Contract).

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

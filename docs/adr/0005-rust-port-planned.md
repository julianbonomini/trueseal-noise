# Go is the reference implementation; Rust port planned for platform portability

Status: superseded (2026-10-12, [#29](https://github.com/julianbonomini/trueseal-noise/issues/29)). Kept for history. The facts below replace the rest of this record:

- The Rust crate in this repo is the only trueseal-noise implementation. There is no `go/` tree and no Go module, and the crate lives at the repo root, not in `rust/`.
- trueseal-relay does not use trueseal-noise. It uses [`github.com/flynn/noise`](https://github.com/flynn/noise) for both its XX Receive Sessions and NK Push Sessions. The two interoperate because both follow the Noise spec, which the Cacophony vectors in `testdata/cacophony.json` check on the Rust side.
- The crate wraps [snow](https://crates.io/crates/snow) instead of hand-assembling RustCrypto primitives. Its dependencies are still pure Rust, with no C toolchain.
- Distribution and versioning follow trueseal-sync [ADR-0030](https://github.com/julianbonomini/trueseal-sync/blob/main/docs/adr/0030-distribution-channels-and-lockstep-versions.md): git tags only, no crates.io publish for the preview, Apache-2.0, and the Cargo version matches each tag from 0.2.0 on.

The original text follows.


The Go implementation of trueseal-noise is the reference: written first, spec-compliant against official test vectors, and used by trueseal-relay (a Go server binary that is never ported).

A Rust port is planned to serve as the canonical portable implementation for the trueseal client stack. The driver is trueseal-sync: the client library must run on iOS, Android, macOS, and Linux. Go cannot compile to iOS (CGo is prohibited on iOS, and Go's runtime requires dynamic linking which Apple's App Store disallows). Rust compiles to all target platforms as a static library and supports automatic Swift and Kotlin binding generation via UniFFI (Mozilla's cross-language binding tool).

The Rust port implements the same spec (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), verified against the same official test vectors. Correctness is language-agnostic — the test vectors are the contract. Raw primitives come from the RustCrypto family (`x25519-dalek`, `chacha20poly1305`, `blake2`), mirroring the Go implementation's use of `golang.org/x/crypto`. RustCrypto is chosen over `ring` for pure-Rust cross-compilation: no C toolchain dependency, no `cmake`/`nasm` requirement, and reliable compilation to all target platforms (iOS, Android, WASM).

## Repository layout

Both implementations live in the same repo, structured as:

```
go/     ← Go reference implementation; module path github.com/julianbonomini/trueseal-noise/go
rust/   ← Rust portable implementation; crate name trueseal-noise (crates.io)
```

`testdata/cacophony.json` (the official test vectors) is the shared correctness contract. Both implementations reference it. Co-location is intentional — keeping the vectors in one place eliminates drift. The repo can be split into two independent repos later without breaking either implementation.

The Go module path is `github.com/julianbonomini/trueseal-noise/go`. The rename from the original root-level path happens while there are zero external consumers — the only moment this costs nothing.

The Rust crate is named `trueseal-noise` in `Cargo.toml` but is not published to crates.io until the implementation is complete and the project is open-sourced. The name is available and will be claimed on first publish.

The Go implementation is not deprecated — it remains the reference and powers trueseal-relay indefinitely.

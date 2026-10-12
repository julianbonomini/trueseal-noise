# trueseal-noise

A Rust implementation of the Noise Protocol Framework — a reusable encrypted transport primitive. The Rust crate is the canonical portable implementation: it compiles to every platform (iOS, Android, macOS, Linux, WASM) and enables Swift/Kotlin bindings via UniFFI. It implements `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_NK_25519_ChaChaPoly_BLAKE2s`, verified against the official cacophony test vectors. The Rust crate is named `trueseal-noise` (not yet published to crates.io).

## Language

**Portable Implementation**:
The Rust crate at the repo root. Compiles to iOS, Android, macOS, Linux, and WASM as a static library. Exposes Swift and Kotlin bindings via UniFFI. Verified against the official Test Vectors for `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_NK_25519_ChaChaPoly_BLAKE2s`.
_Avoid_: mobile implementation, cross-platform version

**UniFFI**:
Mozilla's cross-language binding tool for Rust. Generates Swift and Kotlin bindings from the Rust crate automatically, enabling the Portable Implementation to be consumed natively in iOS and Android apps without hand-written FFI glue.
_Avoid_: bindings generator, FFI layer

**Cipher Suite**:
The combination of cryptographic primitives backing the handshake: X25519 for Diffie-Hellman, ChaCha20-Poly1305 for symmetric encryption, and BLAKE2s for hashing. ChaCha20-Poly1305 is chosen for constant-time software execution — no timing side-channels without hardware AES acceleration.
_Avoid_: algorithm, crypto params

**Handshake Pattern**:
A named sequence of Diffie-Hellman and message steps that determines the security properties of a session — who authenticates whom, and when. This library implements two patterns: `XX` (mutual authentication, no pre-shared knowledge) and `NK` (initiator knows responder's static key, initiator is anonymous to the responder).
_Avoid_: pattern, mode, variant

**XX Pattern** (`Noise_XX_25519_ChaChaPoly_BLAKE2s`):
A three-message handshake where neither peer has prior knowledge of the other's static key. Both peers end up mutually authenticated. The Initiator calls `session_xx::dial`, the Responder calls `session_xx::accept`. Produces a `session_xx::Session` which exposes `remote_public_key()` unconditionally — both sides are always authenticated.
_Avoid_: mutual auth handshake, standard handshake

**NK Pattern** (`Noise_NK_25519_ChaChaPoly_BLAKE2s`):
A two-message handshake where the Initiator already knows the Responder's static public key. The Initiator is anonymous — the Responder never learns the Initiator's static key. The Initiator calls `session_nk::dial` (passing the Responder's known static public key), the Responder calls `session_nk::accept`. Produces a `session_nk::Session` which does not expose `remote_public_key()` — the Initiator already knew it going in, and the Responder never has it.
_Avoid_: anonymous handshake, one-way handshake

**session_xx::Session**:
A fully negotiated, bidirectional encrypted channel produced by the XX Handshake Pattern. Exposes `send`, `receive`, `remote_public_key`, and `close`. `remote_public_key()` returns `[u8; 32]` unconditionally — mutual authentication is a guarantee of the XX pattern.
_Avoid_: XX connection, XX tunnel

**session_nk::Session**:
A fully negotiated, bidirectional encrypted channel produced by the NK Handshake Pattern. Exposes `send`, `receive`, and `close`. Does not expose `remote_public_key()` — the Initiator already knew the Responder's key before the handshake, and the Responder has no Initiator static key by design.
_Avoid_: NK connection, NK tunnel

**SessionInner**:
A `pub(crate)` struct holding the shared post-handshake state used by both `session_xx::Session` and `session_nk::Session`: two `CipherState`s (one per direction), the transport, and a closed flag. Not part of the public API. The handshake pattern affects how `SessionInner` is constructed, not how it behaves afterwards.
_Avoid_: inner session, base session

**Keypair**:
A static X25519 public/private key pair representing a peer's long-term identity. Generated and stored by the caller; passed into the library at dial/accept time. The library never generates or persists keypairs.
_Avoid_: identity, credentials, keys

**Framing**:
A 2-byte big-endian length prefix prepended to every encrypted message by the library. Required because Noise encryption is per-message — without framing, a stream receiver cannot determine message boundaries and cannot decrypt. The caller never sees framing; it is an internal concern of the library. Maximum message size is 65535 bytes (the Noise spec hard cap); chunking larger payloads is the caller's responsibility.
_Avoid_: length-prefix, header, envelope

**Expected Failure**:
A runtime error the caller should handle: I/O errors, malformed handshake messages, connection drops. Returned as `Result<_, String>` from `dial`, `accept`, `send`, or `receive`. Recoverable — the caller may retry or surface to the user.
_Avoid_: error, exception

**Invariant Violation**:
A condition that should be impossible given correct library code: e.g. sending before the handshake completes, a nonce counter overflow. Indicates a bug, not a runtime condition. The library panics — crashing loudly is safer than silently continuing with broken crypto.
_Avoid_: internal error, fatal error

**Prologue**:
Caller-supplied bytes passed to every `dial` and `accept` (both Handshake Patterns, Rust and FFI) and mixed into the Noise handshake hash. Both peers must pass byte-identical prologues; any difference makes the handshake fail on both sides. The library binds the bytes and nothing more: the caller owns their contents, sends any plaintext it wants the peer to see, and checks it. trueseal-sync uses it to bind the Transport Version prefix (sync ADR-0022). An empty prologue is allowed.
_Avoid_: header, preamble, associated data

**Initiator**:
The peer that calls `dial` — sends the first handshake message. In XX, passes only its own Keypair. In NK, also passes the Responder's known static public key.
_Avoid_: client, sender, caller

**Responder**:
The peer that calls `accept` — receives the first handshake message. Always passes only its own Keypair, regardless of pattern.
_Avoid_: server, receiver, listener

**Test Vectors**:
The official Noise Protocol test vectors (published as JSON at noiseprotocol.org) used to verify correctness of the state machine implementation. Passing the vectors for `Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_NK_25519_ChaChaPoly_BLAKE2s` is the correctness baseline — they prove spec-compliance, not just self-consistency.
_Avoid_: golden tests, snapshot tests

## Relationships

- A **Handshake Pattern** is executed between an **Initiator** and a **Responder** to produce a **Session**
- **session_xx::Session** and **session_nk::Session** both wrap a **SessionInner** for their post-handshake behaviour
- **XX Pattern** produces a **session_xx::Session**; **NK Pattern** produces a **session_nk::Session**
- The **Initiator** and **Responder** must supply the same **Prologue** for a **Handshake Pattern** to complete

## Flagged ambiguities

_(none yet)_

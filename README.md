# trueseal-noise

`Noise_XX_25519_ChaChaPoly_BLAKE2s` and `Noise_NK_25519_ChaChaPoly_BLAKE2s` in Rust.

Thin wrapper around [snow](https://crates.io/crates/snow) with framed transport (2-byte length prefix) and [UniFFI](https://github.com/mozilla/uniffi-rs) bindings for Swift and Kotlin. All crypto is pure Rust via RustCrypto — no C dependencies.

Verified byte-for-byte against [Cacophony](https://github.com/centromere/cacophony) test vectors.

---

## Choose a pattern

Two patterns. Pick one before you dial.

|  | **XX** | **NK** |
|--|--------|--------|
| Initiator authenticates | ✓ | ✗ (anonymous) |
| Responder authenticates | ✓ | ✓ |
| Initiator needs responder's key upfront | ✗ | ✓ |
| After handshake: `remote_public_key()` | both sides | responder side only |
| Typical use | device ↔ device | device → relay / client → server |

In the trueseal stack: XX is used between devices (trueseal-sync pairing and sync); NK is used for device-to-relay sessions (trueseal-relay push/receive).

---

## Install

Not yet published to crates.io. Add via path or git:

```toml
[dependencies]
trueseal-noise = { path = "../trueseal-noise/rust" }
```

---

## XX — mutual authentication

Three-message handshake. Both peers prove their static keypair. Neither needs the other's key upfront.

```rust
use std::net::{TcpListener, TcpStream};
use std::thread;
use trueseal_noise::keypair::{generate_keypair, Keypair};
use trueseal_noise::session_xx::{dial, accept};

// --- responder ---
let listener = TcpListener::bind("127.0.0.1:7700").unwrap();
let responder_kp = generate_keypair();

let r_kp = Keypair::new(responder_kp.private(), responder_kp.public_key);
let r_handle = thread::spawn(move || {
    let (conn, _) = listener.accept().unwrap();
    accept(conn, r_kp, b"my-app v1").expect("responder handshake failed")
});

// --- initiator (another thread / process) ---
let initiator_kp = generate_keypair();
let conn = TcpStream::connect("127.0.0.1:7700").unwrap();
let i_session = dial(conn, initiator_kp, b"my-app v1").expect("initiator handshake failed");
let r_session = r_handle.join().unwrap();

// Both sides have the other's authenticated static key.
// Trust policy is yours — the library only guarantees the crypto.
assert_eq!(i_session.remote_public_key(), responder_kp.public_key);

// Framed, encrypted. send/receive are safe to call concurrently.
i_session.send(b"hello").unwrap();
let msg = r_session.receive().unwrap(); // → b"hello"
```

---

## NK — anonymous initiator

Two-message handshake. Initiator is anonymous; responder is authenticated. Initiator must have the responder's static public key before dialing.

```rust
use trueseal_noise::session_nk::{dial, accept};

// --- initiator ---
// Must supply the responder's known static public key.
let i_session = dial(conn, initiator_kp, responder_pub_key, b"my-app v1").expect("dial failed");

// --- responder ---
// No remote_public_key() — initiator identity is not proven.
let r_session = accept(conn, responder_kp, b"my-app v1").expect("accept failed");

i_session.send(b"hello").unwrap();
let msg = r_session.receive().unwrap();
```

---

## Prologue

Every `dial` and `accept` takes a `prologue: &[u8]` (a `sequence<u8>` over UniFFI). The bytes are mixed into the Noise handshake hash, so both peers must pass identical prologues. If they differ by even one byte, the handshake fails on both sides and no `Session` is returned. Pass `&[]` if you have nothing to bind.

The library only binds the bytes. It does not write them to the wire, parse them or check them against anything. The caller owns the contents. In TrueSeal, trueseal-sync and trueseal-relay exchange a short plaintext Transport Version prefix before the handshake, check it themselves, and pass the same bytes as the prologue (sync ADR-0022). A man-in-the-middle that rewrites the prefix then breaks the handshake instead of silently downgrading it.

---

## Keypairs

```rust
use trueseal_noise::keypair::{generate_keypair, Keypair};

// Generate once, persist yourself.
let kp = generate_keypair();          // RFC 7748 clamped X25519 keypair

// Restore from stored bytes.
let kp = Keypair::new(priv_bytes, pub_bytes);

let pub_bytes: [u8; 32] = kp.public_key; // safe to share freely
let priv_bytes: [u8; 32] = kp.private(); // sensitive — zeroed on drop
```

The library never persists keypairs. That's the caller's responsibility.

---

## Session API

Both `session_xx::Session` and `session_nk::Session` expose the same surface:

```rust
session.send(payload: &[u8]) -> Result<(), String>
session.receive()             -> Result<Vec<u8>, String>
session.close()               -> io::Result<()>

// XX only:
session.remote_public_key()   -> [u8; 32]
```

**Limits**
- Max plaintext per message: **65,519 bytes** (65,535 frame − 16-byte AEAD tag). Larger payloads return `Err`.
- `send` and `receive` are safe to call concurrently on the same session.
- All I/O is **blocking**. Wrap in a thread or `spawn_blocking` if you need async.
- Sessions are not resumable after `close()`.

---

## Security properties

- **Forward secrecy** — session keys come from ephemeral DH. Compromise of a long-term keypair does not decrypt past sessions.
- **Mutual authentication (XX)** — `remote_public_key()` is the peer's authenticated static key. Neither side can be impersonated. What you do with that key is up to you.
- **Anonymous initiator (NK)** — the responder learns nothing about the initiator's identity.
- **Prologue binding** — both peers' handshake hashes cover the prologue, so a handshake only completes if both sides passed the same bytes. This authenticates the prologue; it does not hide it or decide what it should contain.
- **Cipher suite** — ChaCha20-Poly1305 + BLAKE2s + X25519. Constant-time on all platforms; no hardware AES dependency.

---

## Spec conformance

```
cargo test --test cacophony
```

Runs every `Noise_NK` and `Noise_XX` message from the Cacophony suite byte-for-byte, including handshake hash verification. The vectors use a non-empty prologue. `cargo test prologue_vectors` also drives them through `dial`/`accept`: transport ciphertexts match the vectors byte-for-byte, `dial`/`accept` interoperate with a peer configured from the vector, and a one-byte prologue change makes that handshake fail. Passing these means interoperability with any other spec-compliant Noise implementation, not just internal self-consistency.

---

## UniFFI bindings (Swift / Kotlin)

The `ffi` module wraps the core API for UniFFI. Callers implement a `NoiseTransport` callback interface (two methods: `read(count)` and `write(data)`) in Swift or Kotlin — no manual FFI glue required.

```sh
cargo build
cargo run --bin uniffi-bindgen -- generate \
  --library target/debug/libtrueseal_noise.dylib \
  --language swift \
  --out-dir bindings/swift
```

If you're building on Apple platforms, start with **trueseal-sync-swift** — it wraps the prebuilt xcframework and gives you the full sync engine, not just the channel layer.

---

## Crate layout

```
src/
  keypair.rs        — Keypair, generate_keypair()
  session_xx.rs     — XX: dial(), accept(), Session
  session_nk.rs     — NK: dial(), accept(), Session
  session.rs        — SessionInner shared transport (not public API)
  framing.rs        — 2-byte length-prefix read/write
  ffi.rs            — UniFFI wrapper (SessionXx, SessionNk, NoiseError, NoiseTransport)
  trueseal_noise.udl    — UniFFI interface definition
tests/
  cacophony.rs      — Cacophony spec-vector conformance
```

---

trueseal-noise is the cryptographic foundation of the [trueseal ecosystem](https://github.com/julianbonomini). The layer above it is **trueseal-sync** — device identity, pairing, group membership, and outbox delivery built on top of these channels.

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
| After handshake: `remote_public_key()` | both sides | not exposed (the initiator already has the key; the responder never learns one) |
| Use in TrueSeal | Receive Session (device ↔ relay) | Push Session (device → relay) |

In the TrueSeal stack, devices never open Noise sessions to each other. Every session runs between a device and trueseal-relay:

- **Receive Session (XX).** Long-lived. The device authenticates with its stable noise keypair, and the relay delivers that device's inbound Blobs over it.
- **Push Session (NK).** Short-lived. The device uses a fresh ephemeral keypair for each push, so the handshake proves nothing about the sender. The device checks the relay's static key.

End-to-end encryption between devices is done by trueseal-sync above this layer, not by these sessions. See the [Threat Model](https://trueseal.dev/docs/trust/threat-model) for which properties TrueSeal claims and which it doesn't.

---

## Install

Not published to crates.io. Depend on a release tag:

```toml
[dependencies]
trueseal-noise = { git = "https://github.com/julianbonomini/trueseal-noise", tag = "vX.Y.Z" }
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

// Framed, encrypted. See "Limits" below for the threading contract.
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
- Max plaintext per message: **65,519 bytes**. The frame length prefix is a u16, so a frame holds at most 65,535 bytes, and the 16-byte AEAD tag takes 16 of them. `send` returns `Err` for a larger payload and writes nothing; the session stays usable. Rust callers can read the value as `trueseal_noise::MAX_PLAINTEXT_SIZE`.
- trueseal-sync derives its Envelope limit and its 61,440-byte Protocol Size Limit from this ceiling, and the relay's envelope ceiling follows from it ([trueseal-sync ADR-0025](https://github.com/julianbonomini/trueseal-sync/blob/main/docs/adr/0025-single-frame-size-limit.md)). Raising it means widening the length prefix, which needs a Transport Version bump.
- A session can be shared across threads (`Arc<Session>`). Concurrent `send` calls are serialised so frames reach the wire in nonce order; concurrent `receive` calls are serialised so each returns one whole frame.
- `send` can overlap `receive` only if the transport's `read()` and `write()` return `WouldBlock` (or make progress) instead of blocking. A blocking I/O call holds the connection until it returns. Call `set_nonblocking(true)` on a `TcpStream` before `dial`/`accept` to get overlap; the handshake, `send`, and `receive` retry on `WouldBlock`/`Interrupted`. `send` retains its frame offset after a partial write and releases the connection between attempts, so a full send buffer waits for space without starving `receive` or letting another sender overtake it.
- A terminal write error (including a zero-byte write) after encryption advances the nonce returns `Err` and automatically makes the session closed/unusable, even when no frame bytes were written. Later and queued sends/receives reject; retry loops observe closure. Establish a new connection rather than retrying the failed frame. `WouldBlock`/`Interrupted` remain retryable; no send timeout is provided.
- All I/O is **blocking**. Wrap in a thread or `spawn_blocking` if you need async.
- `dial`, `accept`, `send`, and `receive` have no internal deadline. The caller's `Read + Write` transport must stop stalled I/O with a terminal error such as `TimedOut` or `UnexpectedEof`; `WouldBlock` and `Interrupted` are retried indefinitely while the session remains open. An OS socket timeout that returns `WouldBlock` is therefore not a Noise deadline. For non-blocking TCP, use a caller-owned adapter that checks an absolute deadline before each I/O attempt and returns `TimedOut` when it expires.
- `close()` marks the session unusable without closing the caller's transport. Pending nonblocking receives return `Err` when they next observe closure, including partial header/body reads; queued and subsequent receives reject. Send retry loops also observe closure. An already-blocked transport `read()` or `write()` is **not** forcibly interrupted: the caller still owns deadlines/shutdown. Sessions are not resumable after closure.

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

`tests/adversarial.rs` drives public XX/NK `dial`, `accept`, and `receive` against a snow peer over loopback TCP. It covers truncated and tampered handshakes, stale authenticated handshake messages and wrong-role replays, transport tampering/replay/reordering, invalid zero-byte frame bodies, declared lengths longer than the available body followed by EOF, the wrong NK responder key, and peer close during the handshake. Complete hostile messages keep the peer connected and must fail at the attacked Noise parsing/authentication step; EOF and deadline errors cannot satisfy those assertions. Authenticated empty application payloads remain valid: their frames contain a 16-byte tag. A fresh Noise handshake does not provide a cache that rejects every replayed first message; the replay tests cover invalid transcript/state reuse, not application replay protection.

Silent-peer tests supply an absolute deadline in the caller's transport. Terminal `TimedOut`/`UnexpectedEof` tests cover handshake and receive failures, including partial frame headers and bodies. Existing `cargo test tcp_send_backpressure -- --nocapture` coverage from [#35](https://github.com/julianbonomini/trueseal-noise/issues/35) fills a real non-blocking TCP send buffer and checks that XX/NK decrypt every frame once it drains; it does not claim a built-in send deadline.

---

## UniFFI bindings (Swift / Kotlin)

The `ffi` module wraps the core API for UniFFI. Callers implement a `NoiseTransport` callback interface (two methods: `read(count)` and `write(data)`) in Swift or Kotlin — no manual FFI glue required.

`SessionXx` and `SessionNk` have the same closed-state guarantees as Rust sessions. A terminal `NoiseTransport.write` failure after nonce advancement makes the session unusable; later/queued operations return `NoiseError::Closed`. `close()` never shuts down the callback transport. An already-blocked callback must return through the caller's deadline or shutdown before it can observe closure.

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
  adversarial.rs    — public XX/NK hostile-input and caller-deadline coverage
```

---

trueseal-noise is the cryptographic foundation of the [trueseal ecosystem](https://github.com/julianbonomini). The layer above it is **trueseal-sync** — device identity, pairing, group membership, and outbox delivery built on top of these channels.

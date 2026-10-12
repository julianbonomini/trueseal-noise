//! Drives the Cacophony vectors, which use a non-empty prologue, through the
//! public `dial`/`accept` handshake code rather than through `snow` directly.
//!
//! `dial`/`accept` send empty handshake payloads while the vectors carry
//! non-empty ones, so handshake ciphertexts cannot match byte-for-byte. The
//! tests therefore check:
//!
//! 1. With the vector's static keys, ephemeral keys and prologue, a
//!    `dial`/`accept` pair completes and produces the vector's transport
//!    ciphertexts byte-for-byte.
//! 2. `dial` and `accept` interoperate with a `snow` peer configured exactly
//!    as the vector specifies (the configuration `tests/cacophony.rs` proves
//!    byte-exact), and fail against it when our prologue differs by one byte.
//!    Point 2 is what proves the prologue bytes reach the handshake hash.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::framing::{read_frame, write_frame};
use crate::keypair::Keypair;
use crate::test_helpers::tcp_pair;
use crate::{session_nk, session_xx};

// ── Vector loading ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Suite {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    protocol_name: String,
    init_prologue: String,
    init_static: Option<String>,
    init_ephemeral: String,
    init_remote_static: Option<String>,
    resp_prologue: String,
    resp_static: String,
    resp_ephemeral: String,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Message {
    payload: String,
    ciphertext: String,
}

fn load_vectors() -> Vec<Vector> {
    let suite: Suite = serde_json::from_str(include_str!("../testdata/cacophony.json"))
        .expect("parse cacophony.json");
    assert!(!suite.vectors.is_empty(), "no vectors loaded");
    for v in &suite.vectors {
        assert!(
            !v.init_prologue.is_empty() && v.init_prologue == v.resp_prologue,
            "[{}] expected a shared non-empty prologue",
            v.protocol_name
        );
    }
    suite.vectors
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|_| panic!("bad hex: {s}"))
}

fn arr(s: &str) -> [u8; 32] {
    h(s).try_into().expect("expected 32 bytes")
}

fn keypair(private_hex: &str) -> Keypair {
    let private = arr(private_hex);
    let public = PublicKey::from(&StaticSecret::from(private));
    Keypair::new(private, *public.as_bytes())
}

fn is_nk(v: &Vector) -> bool {
    v.protocol_name.contains("_NK_")
}

fn hs_msg_count(v: &Vector) -> usize {
    if is_nk(v) {
        2
    } else {
        3
    }
}

// ── Transport plumbing ────────────────────────────────────────────────────────

/// TCP stream that records every byte written through it.
struct Tap {
    inner: TcpStream,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Tap {
    fn new(inner: TcpStream) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                inner,
                written: written.clone(),
            },
            written,
        )
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn split_frames(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        frames.push(bytes[2..2 + len].to_vec());
        bytes = &bytes[2 + len..];
    }
    frames
}

/// Common surface of the two Session types, so one runner covers both.
trait Duplex {
    fn send(&self, payload: &[u8]) -> Result<(), String>;
    fn receive(&self) -> Result<Vec<u8>, String>;
}

impl<T: Read + Write + Send> Duplex for session_xx::Session<T> {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        session_xx::Session::send(self, payload)
    }
    fn receive(&self) -> Result<Vec<u8>, String> {
        session_xx::Session::receive(self)
    }
}

impl<T: Read + Write + Send> Duplex for session_nk::Session<T> {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        session_nk::Session::send(self, payload)
    }
    fn receive(&self) -> Result<Vec<u8>, String> {
        session_nk::Session::receive(self)
    }
}

type BoxedSession = Box<dyn Duplex + Send>;

/// Runs `dial` with the vector's Initiator keys and the given prologue.
fn dial_vector<T: Read + Write + Send + 'static>(
    v: &Vector,
    conn: T,
    prologue: &[u8],
) -> Result<BoxedSession, String> {
    let eph = h(&v.init_ephemeral);
    if is_nk(v) {
        // NK Initiators are anonymous; the vector has no init_static, and
        // dial ignores the keypair's static key for NK.
        let kp = Keypair::new([0u8; 32], [0u8; 32]);
        let rs = arr(v
            .init_remote_static
            .as_deref()
            .expect("NK init_remote_static"));
        session_nk::dial_with_fixed_ephemeral(conn, kp, rs, prologue, &eph)
            .map(|s| Box::new(s) as BoxedSession)
    } else {
        let kp = keypair(v.init_static.as_deref().expect("XX init_static"));
        session_xx::dial_with_fixed_ephemeral(conn, kp, prologue, &eph)
            .map(|s| Box::new(s) as BoxedSession)
    }
}

/// Runs `accept` with the vector's Responder keys and the given prologue.
fn accept_vector<T: Read + Write + Send + 'static>(
    v: &Vector,
    conn: T,
    prologue: &[u8],
) -> Result<BoxedSession, String> {
    let eph = h(&v.resp_ephemeral);
    let kp = keypair(&v.resp_static);
    if is_nk(v) {
        session_nk::accept_with_fixed_ephemeral(conn, kp, prologue, &eph)
            .map(|s| Box::new(s) as BoxedSession)
    } else {
        session_xx::accept_with_fixed_ephemeral(conn, kp, prologue, &eph)
            .map(|s| Box::new(s) as BoxedSession)
    }
}

/// Builds a snow HandshakeState configured exactly as the vector specifies.
fn snow_vector_peer(v: &Vector, initiator: bool) -> snow::HandshakeState {
    let params: snow::params::NoiseParams = v.protocol_name.parse().expect("protocol");
    // Keep the key material alive for the builder borrows.
    let prologue = h(if initiator {
        &v.init_prologue
    } else {
        &v.resp_prologue
    });
    let eph = h(if initiator {
        &v.init_ephemeral
    } else {
        &v.resp_ephemeral
    });
    let local_static = if initiator {
        v.init_static.as_deref().map(h)
    } else {
        Some(h(&v.resp_static))
    };
    let remote_static = if initiator {
        v.init_remote_static.as_deref().map(h)
    } else {
        None
    };

    let mut b = snow::Builder::new(params)
        .prologue(&prologue)
        .expect("prologue")
        .fixed_ephemeral_key_for_testing_only(&eph);
    if let Some(ref s) = local_static {
        b = b.local_private_key(s).expect("local static");
    }
    if let Some(ref rs) = remote_static {
        b = b.remote_public_key(rs).expect("remote static");
    }
    if initiator {
        b.build_initiator().expect("build initiator")
    } else {
        b.build_responder().expect("build responder")
    }
}

/// Runs the handshake for a snow peer over conn with empty payloads (matching
/// what dial/accept send), then checks one transport message each way.
fn run_snow_peer(
    v: &Vector,
    mut conn: TcpStream,
    initiator: bool,
) -> Result<snow::TransportState, String> {
    let mut hs = snow_vector_peer(v, initiator);
    let mut buf = vec![0u8; 65535];
    for i in 0..hs_msg_count(v) {
        let we_send = (i % 2 == 0) == initiator;
        if we_send {
            let len = hs
                .write_message(&[], &mut buf)
                .map_err(|e| format!("{e:?}"))?;
            write_frame(&mut conn, &buf[..len]).map_err(|e| e.to_string())?;
        } else {
            let msg = read_frame(&mut conn).map_err(|e| e.to_string())?;
            hs.read_message(&msg, &mut buf)
                .map_err(|e| format!("{e:?}"))?;
        }
    }
    let mut t = hs.into_transport_mode().map_err(|e| format!("{e:?}"))?;

    // Receive one message from our side, then answer.
    let msg = read_frame(&mut conn).map_err(|e| e.to_string())?;
    let mut pt = vec![0u8; 65535];
    let n = t
        .read_message(&msg, &mut pt)
        .map_err(|e| format!("{e:?}"))?;
    let len = t
        .write_message(&pt[..n], &mut buf)
        .map_err(|e| format!("{e:?}"))?;
    write_frame(&mut conn, &buf[..len]).map_err(|e| e.to_string())?;
    Ok(t)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn vectors_through_dial_accept_produce_vector_transport_ciphertexts() {
    for v in load_vectors() {
        let name = v.protocol_name.clone();
        let v = Arc::new(v);
        let n_hs = hs_msg_count(&v);

        let (i_conn, r_conn) = tcp_pair();
        let (i_tap, i_written) = Tap::new(i_conn);
        let (r_tap, r_written) = Tap::new(r_conn);

        let v_r = v.clone();
        let r_handle = std::thread::spawn(move || {
            let prologue = h(&v_r.resp_prologue);
            accept_vector(&v_r, r_tap, &prologue)
        });
        let i_session = dial_vector(&v, i_tap, &h(&v.init_prologue))
            .unwrap_or_else(|e| panic!("[{name}] dial failed: {e}"));
        let r_session = r_handle
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("[{name}] accept failed: {e}"));

        // Transport phase, using the same direction convention as
        // tests/cacophony.rs: the party that received the last handshake
        // message sends first.
        let resp_sends_first = (n_hs - 1).is_multiple_of(2);
        let mut expected_i = Vec::new();
        let mut expected_r = Vec::new();
        for (t_idx, msg) in v.messages[n_hs..].iter().enumerate() {
            let init_sends = if resp_sends_first {
                t_idx % 2 != 0
            } else {
                t_idx % 2 == 0
            };
            let (sender, receiver, expected) = if init_sends {
                (&i_session, &r_session, &mut expected_i)
            } else {
                (&r_session, &i_session, &mut expected_r)
            };
            let payload = h(&msg.payload);
            sender
                .send(&payload)
                .unwrap_or_else(|e| panic!("[{name}] send {t_idx}: {e}"));
            let got = receiver
                .receive()
                .unwrap_or_else(|e| panic!("[{name}] receive {t_idx}: {e}"));
            assert_eq!(got, payload, "[{name}] transport {t_idx} plaintext");
            expected.push(h(&msg.ciphertext));
        }

        let i_frames = split_frames(&i_written.lock().unwrap());
        let r_frames = split_frames(&r_written.lock().unwrap());
        let i_hs = n_hs.div_ceil(2);
        let r_hs = n_hs / 2;

        // First handshake message starts with the Initiator's ephemeral
        // public key, which must be the vector's.
        assert_eq!(
            i_frames[0][..32],
            h(&v.messages[0].ciphertext)[..32],
            "[{name}] initiator ephemeral"
        );
        assert_eq!(
            i_frames[i_hs..],
            expected_i[..],
            "[{name}] initiator transport ciphertexts"
        );
        assert_eq!(
            r_frames[r_hs..],
            expected_r[..],
            "[{name}] responder transport ciphertexts"
        );
    }
}

#[test]
fn dial_and_accept_interoperate_with_vector_configured_peer() {
    for v in load_vectors() {
        let name = v.protocol_name.clone();
        let v = Arc::new(v);

        // Our dial against a snow Responder built from the vector.
        let (i_conn, r_conn) = tcp_pair();
        let v_r = v.clone();
        let peer = std::thread::spawn(move || run_snow_peer(&v_r, r_conn, false));
        let session = dial_vector(&v, i_conn, &h(&v.init_prologue))
            .unwrap_or_else(|e| panic!("[{name}] dial vs vector peer: {e}"));
        session.send(b"interop").expect("send");
        assert_eq!(session.receive().expect("receive"), b"interop");
        peer.join()
            .unwrap()
            .unwrap_or_else(|e| panic!("[{name}] vector responder: {e}"));

        // A snow Initiator built from the vector against our accept.
        let (i_conn, r_conn) = tcp_pair();
        let v_i = v.clone();
        let peer = std::thread::spawn(move || run_snow_peer(&v_i, i_conn, true));
        let session = accept_vector(&v, r_conn, &h(&v.resp_prologue))
            .unwrap_or_else(|e| panic!("[{name}] accept vs vector peer: {e}"));
        session.send(b"interop").expect("send");
        assert_eq!(session.receive().expect("receive"), b"interop");
        peer.join()
            .unwrap()
            .unwrap_or_else(|e| panic!("[{name}] vector initiator: {e}"));
    }
}

#[test]
fn one_byte_prologue_change_breaks_interop_with_vector_peer() {
    for v in load_vectors() {
        let name = v.protocol_name.clone();
        let v = Arc::new(v);
        let mut tampered = h(&v.init_prologue);
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        // dial with a tampered prologue against the vector Responder.
        let (i_conn, r_conn) = tcp_pair();
        let v_r = v.clone();
        let peer = std::thread::spawn(move || run_snow_peer(&v_r, r_conn, false));
        let ours = dial_vector(&v, i_conn, &tampered);
        let theirs = peer.join().unwrap();
        assert!(
            ours.is_err(),
            "[{name}] dial must fail with tampered prologue"
        );
        assert!(theirs.is_err(), "[{name}] vector responder must fail");

        // accept with a tampered prologue against the vector Initiator.
        let (i_conn, r_conn) = tcp_pair();
        let v_i = v.clone();
        let peer = std::thread::spawn(move || run_snow_peer(&v_i, i_conn, true));
        let ours = accept_vector(&v, r_conn, &tampered);
        let theirs = peer.join().unwrap();
        assert!(
            ours.is_err(),
            "[{name}] accept must fail with tampered prologue"
        );
        assert!(theirs.is_err(), "[{name}] vector initiator must fail");
    }
}

//! Failure-boundary coverage through the public XX/NK dial, accept and Session APIs.
//! The peer is a real loopback TCP transport driven by snow, not SessionInner.
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use trueseal_noise::keypair::{generate_keypair, Keypair};
use trueseal_noise::{session_nk, session_xx};

const PROLOGUE: &[u8] = b"NOISE-3 adversarial boundary";
const BOUND: Duration = Duration::from_secs(5);
const SILENT_DEADLINE: Duration = Duration::from_millis(100);
const DEADLINE_ERROR: &str = "caller transport deadline expired";

#[derive(Clone, Copy, Debug)]
enum Pattern {
    Xx,
    Nk,
}

impl Pattern {
    fn name(self) -> &'static str {
        match self {
            Self::Xx => "Noise_XX_25519_ChaChaPoly_BLAKE2s",
            Self::Nk => "Noise_NK_25519_ChaChaPoly_BLAKE2s",
        }
    }

    fn dial(self, conn: DeadlineTcp, key: Keypair, remote: [u8; 32]) -> Result<Session, String> {
        match self {
            Self::Xx => session_xx::dial(conn, key, PROLOGUE).map(Session::Xx),
            Self::Nk => session_nk::dial(conn, key, remote, PROLOGUE).map(Session::Nk),
        }
    }

    fn accept(self, conn: DeadlineTcp, key: Keypair) -> Result<Session, String> {
        match self {
            Self::Xx => session_xx::accept(conn, key, PROLOGUE).map(Session::Xx),
            Self::Nk => session_nk::accept(conn, key, PROLOGUE).map(Session::Nk),
        }
    }
}

enum Session {
    Xx(session_xx::Session<DeadlineTcp>),
    Nk(session_nk::Session<DeadlineTcp>),
}

impl Session {
    fn send(&self, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::Xx(s) => s.send(payload),
            Self::Nk(s) => s.send(payload),
        }
    }

    fn receive(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Xx(s) => s.receive(),
            Self::Nk(s) => s.receive(),
        }
    }

    fn close(&self) -> io::Result<()> {
        match self {
            Self::Xx(s) => s.close(),
            Self::Nk(s) => s.close(),
        }
    }
}

#[derive(Default)]
struct ReadFailure {
    kind: AtomicU8,
    after: AtomicUsize,
}

impl ReadFailure {
    fn arm(&self, kind: ErrorKind, after: usize) {
        self.after.store(after, Ordering::Release);
        self.kind.store(
            if kind == ErrorKind::TimedOut { 1 } else { 2 },
            Ordering::Release,
        );
    }
}

// An absolute deadline belongs to this caller-provided Read + Write adapter.
// Socket read_timeout alone is insufficient: on Unix its expiry may be WouldBlock,
// which Noise intentionally retries. No library timeout API is assumed here.
struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
    read_error: Arc<ReadFailure>,
}

impl DeadlineTcp {
    fn new(stream: TcpStream) -> Self {
        stream.set_nonblocking(true).unwrap();
        Self {
            stream,
            deadline: Instant::now() + BOUND,
            read_error: Arc::new(ReadFailure::default()),
        }
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            Err(io::Error::new(ErrorKind::TimedOut, DEADLINE_ERROR))
        } else {
            Ok(())
        }
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        let kind = self.read_error.kind.load(Ordering::Acquire);
        let allowed = self.read_error.after.load(Ordering::Acquire);
        if kind != 0 && allowed == 0 {
            let kind = if kind == 1 {
                ErrorKind::TimedOut
            } else {
                ErrorKind::UnexpectedEof
            };
            return Err(io::Error::new(kind, "injected caller read failure"));
        }
        let n = if kind == 0 {
            out.len()
        } else {
            out.len().min(allowed)
        };
        let result = self.stream.read(&mut out[..n]);
        if kind != 0 {
            if let Ok(n) = result {
                self.read_error.after.fetch_sub(n, Ordering::AcqRel);
            }
        }
        result
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_deadline()?;
        self.stream.flush()
    }
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let caller = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(BOUND)).unwrap();
    peer.set_write_timeout(Some(BOUND)).unwrap();
    (caller, peer)
}

fn read_frame(peer: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 2];
    peer.read_exact(&mut header).unwrap();
    let mut body = vec![0; u16::from_be_bytes(header) as usize];
    peer.read_exact(&mut body).unwrap();
    body
}

fn write_frame(peer: &mut TcpStream, body: &[u8]) {
    peer.write_all(&(body.len() as u16).to_be_bytes()).unwrap();
    peer.write_all(body).unwrap();
}

fn handshake(
    pattern: Pattern,
    initiator: bool,
    key: &Keypair,
    remote: &Keypair,
) -> snow::HandshakeState {
    let private = key.private();
    let mut builder = snow::Builder::new(pattern.name().parse().unwrap())
        .prologue(PROLOGUE)
        .unwrap()
        .local_private_key(&private)
        .unwrap();
    if initiator && matches!(pattern, Pattern::Nk) {
        builder = builder.remote_public_key(&remote.public_key).unwrap();
    }
    if initiator {
        builder.build_initiator().unwrap()
    } else {
        builder.build_responder().unwrap()
    }
}

fn message(hs: &mut snow::HandshakeState) -> Vec<u8> {
    let mut out = vec![0; 65535];
    let len = hs.write_message(&[], &mut out).unwrap();
    out.truncate(len);
    out
}

fn consume(hs: &mut snow::HandshakeState, body: &[u8]) {
    hs.read_message(body, &mut [0; 65535]).unwrap();
}

// Capture a completed, independent handshake. Reusing its authenticated response
// or XX final message in a fresh transcript must not authenticate the old peer.
fn transcript(pattern: Pattern, initiator: &Keypair, responder: &Keypair) -> Vec<Vec<u8>> {
    let mut i = handshake(pattern, true, initiator, responder);
    let mut r = handshake(pattern, false, responder, initiator);
    let first = message(&mut i);
    consume(&mut r, &first);
    let second = message(&mut r);
    consume(&mut i, &second);
    let mut frames = vec![first, second];
    if matches!(pattern, Pattern::Xx) {
        let third = message(&mut i);
        consume(&mut r, &third);
        frames.push(third);
    }
    frames
}

fn bounded<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        tx.send(operation()).unwrap();
    });
    let result = rx.recv_timeout(BOUND + Duration::from_secs(1));
    if result.is_ok() {
        worker.join().expect("public operation panicked");
    }
    result.expect("public operation did not finish within caller deadline")
}

#[derive(Clone, Copy, Debug)]
enum Attack {
    TruncatedHeader,
    TruncatedBody,
    TruncatedMessage,
    BitFlipped,
    Replayed,
    Close,
    OversizedThenEof,
}

fn attack_frame(peer: &mut TcpStream, mut body: Vec<u8>, attack: Attack, replay: &[u8]) {
    match attack {
        Attack::TruncatedHeader => peer.write_all(&[0]).unwrap(),
        Attack::TruncatedBody => {
            peer.write_all(&(body.len() as u16).to_be_bytes()).unwrap();
            peer.write_all(&body[..body.len() - 1]).unwrap();
        }
        Attack::TruncatedMessage => {
            body.pop();
            write_frame(peer, &body);
        }
        Attack::BitFlipped => {
            *body.last_mut().unwrap() ^= 1;
            write_frame(peer, &body);
        }
        Attack::Replayed => write_frame(peer, replay),
        Attack::Close => (),
        Attack::OversizedThenEof => peer.write_all(&[0xff, 0xff, 1, 2, 3]).unwrap(),
    }
    peer.shutdown(Shutdown::Both).unwrap();
}

fn rejected_handshake(pattern: Pattern, dial: bool, attack: Attack, final_xx: bool) {
    let i = generate_keypair();
    let r = generate_keypair();
    let old = transcript(pattern, &i, &r);
    let (conn, mut peer) = tcp_pair();
    let public_key = r.public_key;
    let mut hs = if dial {
        handshake(pattern, false, &r, &i)
    } else {
        handshake(pattern, true, &i, &r)
    };
    let worker = thread::spawn(move || {
        bounded(move || {
            if dial {
                pattern.dial(DeadlineTcp::new(conn), i, public_key)
            } else {
                pattern.accept(DeadlineTcp::new(conn), r)
            }
        })
    });
    let (body, replay) = if dial {
        consume(&mut hs, &read_frame(&mut peer));
        (message(&mut hs), &old[1])
    } else if final_xx {
        write_frame(&mut peer, &message(&mut hs));
        consume(&mut hs, &read_frame(&mut peer));
        (message(&mut hs), &old[2])
    } else {
        // Replaying the responder's old message as an initiator message is an
        // invalid role/state replay. An NK msg0 replay to the same static key
        // is not intrinsically invalid; Noise has no handshake replay cache.
        (message(&mut hs), &old[1])
    };
    attack_frame(&mut peer, body, attack, replay);
    let result = worker.join().expect("handshake panicked");
    assert!(
        result.is_err(),
        "{pattern:?} {} {attack:?} unexpectedly completed",
        if dial { "dial" } else { "accept" }
    );
}

fn handshake_matrix(pattern: Pattern, attack: Attack) {
    rejected_handshake(pattern, true, attack, false);
    rejected_handshake(pattern, false, attack, matches!(pattern, Pattern::Xx));
    if matches!(pattern, Pattern::Xx) && !matches!(attack, Attack::BitFlipped | Attack::Replayed) {
        rejected_handshake(pattern, false, attack, false);
    }
}

// Returns a public Session and its connected, negotiated snow peer. This exercises
// dial/accept rather than manufacturing private SessionInner transport state.
fn connected(
    pattern: Pattern,
    dial: bool,
    conn: DeadlineTcp,
    mut peer: TcpStream,
) -> (Session, TcpStream, snow::TransportState) {
    let i = generate_keypair();
    let r = generate_keypair();
    let remote = r.public_key;
    let mut hs = if dial {
        handshake(pattern, false, &r, &i)
    } else {
        handshake(pattern, true, &i, &r)
    };
    let worker = thread::spawn(move || {
        bounded(move || {
            if dial {
                pattern.dial(conn, i, remote)
            } else {
                pattern.accept(conn, r)
            }
        })
    });
    if dial {
        consume(&mut hs, &read_frame(&mut peer));
        write_frame(&mut peer, &message(&mut hs));
        if matches!(pattern, Pattern::Xx) {
            consume(&mut hs, &read_frame(&mut peer));
        }
    } else {
        write_frame(&mut peer, &message(&mut hs));
        consume(&mut hs, &read_frame(&mut peer));
        if matches!(pattern, Pattern::Xx) {
            write_frame(&mut peer, &message(&mut hs));
        }
    }
    let session = worker.join().unwrap().expect("setup handshake failed");
    (session, peer, hs.into_transport_mode().unwrap())
}

fn transport_message(peer: &mut snow::TransportState, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0; payload.len() + 16];
    let len = peer.write_message(payload, &mut out).unwrap();
    out.truncate(len);
    out
}

#[derive(Clone, Copy, Debug)]
enum TransportAttack {
    Tampered,
    Replayed,
    Reordered,
    ZeroLength,
    OversizedThenEof,
}

fn transport_matrix(pattern: Pattern, attack: TransportAttack) {
    for dial in [true, false] {
        let (conn, peer) = tcp_pair();
        let (session, mut peer, mut crypto) =
            connected(pattern, dial, DeadlineTcp::new(conn), peer);
        match attack {
            TransportAttack::Tampered => {
                let mut body = transport_message(&mut crypto, b"authenticated");
                body[0] ^= 1;
                write_frame(&mut peer, &body);
            }
            TransportAttack::Replayed => {
                let body = transport_message(&mut crypto, b"deliver once");
                write_frame(&mut peer, &body);
                assert_eq!(session.receive().unwrap(), b"deliver once");
                write_frame(&mut peer, &body);
            }
            TransportAttack::Reordered => {
                let first = transport_message(&mut crypto, b"first");
                let second = transport_message(&mut crypto, b"second");
                write_frame(&mut peer, &second);
                write_frame(&mut peer, &first);
            }
            TransportAttack::ZeroLength => write_frame(&mut peer, &[]),
            TransportAttack::OversizedThenEof => {
                peer.write_all(&[0xff, 0xff, 1, 2, 3]).unwrap();
            }
        }
        peer.shutdown(Shutdown::Both).unwrap();
        let result = bounded(move || session.receive());
        assert!(
            result.is_err(),
            "{pattern:?} dial={dial} {attack:?} accepted"
        );
    }
}

fn silent_peer(pattern: Pattern) {
    for dial in [true, false] {
        let (conn, _silent_peer) = tcp_pair();
        let mut conn = DeadlineTcp::new(conn);
        conn.deadline = Instant::now() + SILENT_DEADLINE;
        let key = generate_keypair();
        let remote = generate_keypair().public_key;
        let result = bounded(move || {
            if dial {
                pattern.dial(conn, key, remote)
            } else {
                pattern.accept(conn, key)
            }
        });
        let error = result
            .err()
            .expect("silent handshake unexpectedly succeeded");
        assert!(
            error.contains(DEADLINE_ERROR),
            "wrong deadline owner: {error}"
        );
        eprintln!(
            "{pattern:?} {} silent peer: Err({error}) within caller-owned deadline",
            if dial { "dial" } else { "accept" }
        );
    }
    for dial in [true, false] {
        let (conn, peer) = tcp_pair();
        let mut conn = DeadlineTcp::new(conn);
        // Budget includes setup; no unrelated work can extend this absolute deadline.
        conn.deadline = Instant::now() + Duration::from_secs(1);
        let (session, _silent_peer, _) = connected(pattern, dial, conn, peer);
        let error = bounded(move || session.receive()).unwrap_err();
        assert!(
            error.contains(DEADLINE_ERROR),
            "wrong deadline owner: {error}"
        );
        eprintln!(
            "{pattern:?} dial={dial} silent receive: Err({error}) within caller-owned deadline"
        );
    }
}

fn transport_errors(pattern: Pattern) {
    for kind in [ErrorKind::TimedOut, ErrorKind::UnexpectedEof] {
        for dial in [true, false] {
            let (conn, _peer) = tcp_pair();
            let conn = DeadlineTcp::new(conn);
            conn.read_error.arm(kind, 0);
            let key = generate_keypair();
            let remote = generate_keypair().public_key;
            let result = bounded(move || {
                if dial {
                    pattern.dial(conn, key, remote)
                } else {
                    pattern.accept(conn, key)
                }
            });
            let error = result.err().expect("handshake ignored terminal read error");
            assert!(error.contains("injected caller read failure"), "{error}");

            for after in [0, 1, 2, 3] {
                let (conn, peer) = tcp_pair();
                let conn = DeadlineTcp::new(conn);
                let failure = conn.read_error.clone();
                let (session, mut peer, _) = connected(pattern, dial, conn, peer);
                peer.write_all(&[0, 16, 0][..after]).unwrap();
                failure.arm(kind, after);
                let error = bounded(move || session.receive()).unwrap_err();
                assert!(error.contains("injected caller read failure"), "{error}");
            }
        }
    }
}

fn authenticated_empty_payload(pattern: Pattern) {
    for dial in [true, false] {
        let (conn, peer) = tcp_pair();
        let (session, mut peer, mut crypto) =
            connected(pattern, dial, DeadlineTcp::new(conn), peer);
        write_frame(&mut peer, &transport_message(&mut crypto, &[]));
        assert!(session.receive().unwrap().is_empty());
        session.send(&[]).unwrap();
        let mut plaintext = [0; 16];
        assert_eq!(
            crypto
                .read_message(&read_frame(&mut peer), &mut plaintext)
                .unwrap(),
            0
        );
    }
}

fn subsequent_receive_after_close(pattern: Pattern) {
    let (conn, peer) = tcp_pair();
    let (session, _peer, _) = connected(pattern, true, DeadlineTcp::new(conn), peer);
    session.close().unwrap();
    assert!(bounded(move || session.receive()).is_err());
}

macro_rules! pattern_tests {
    ($module:ident, $pattern:expr) => {
        mod $module {
            use super::*;
            #[test]
            fn truncated_handshake_header() {
                handshake_matrix($pattern, Attack::TruncatedHeader);
            }
            #[test]
            fn truncated_handshake_body() {
                handshake_matrix($pattern, Attack::TruncatedBody);
            }
            #[test]
            fn truncated_noise_handshake_message() {
                handshake_matrix($pattern, Attack::TruncatedMessage);
            }
            #[test]
            fn bit_flipped_authenticated_handshake() {
                handshake_matrix($pattern, Attack::BitFlipped);
            }
            #[test]
            fn replayed_handshake_wrong_transcript_or_role() {
                handshake_matrix($pattern, Attack::Replayed);
            }
            #[test]
            fn peer_closes_mid_handshake() {
                handshake_matrix($pattern, Attack::Close);
            }
            #[test]
            fn oversized_handshake_length_then_eof() {
                handshake_matrix($pattern, Attack::OversizedThenEof);
            }
            #[test]
            fn tampered_transport() {
                transport_matrix($pattern, TransportAttack::Tampered);
            }
            #[test]
            fn replayed_transport() {
                transport_matrix($pattern, TransportAttack::Replayed);
            }
            #[test]
            fn reordered_transport() {
                transport_matrix($pattern, TransportAttack::Reordered);
            }
            #[test]
            fn zero_length_transport_frame() {
                transport_matrix($pattern, TransportAttack::ZeroLength);
            }
            #[test]
            fn oversized_transport_length_then_eof() {
                transport_matrix($pattern, TransportAttack::OversizedThenEof);
            }
            #[test]
            fn authenticated_empty_payload_is_not_zero_length_frame() {
                authenticated_empty_payload($pattern);
            }
            #[test]
            fn caller_owned_deadline_ends_silent_dial_accept_receive() {
                silent_peer($pattern);
            }
            #[test]
            fn timed_out_and_unexpected_eof_end_dial_accept_receive() {
                transport_errors($pattern);
            }
            #[test]
            fn closed_session_rejects_subsequent_receive() {
                subsequent_receive_after_close($pattern);
            }
        }
    };
}

pattern_tests!(xx, Pattern::Xx);
pattern_tests!(nk, Pattern::Nk);

#[test]
fn nk_wrong_responder_key_rejected_by_both_peers() {
    let responder = generate_keypair();
    let wrong_remote = generate_keypair().public_key;
    let (conn, peer) = tcp_pair();
    let worker = thread::spawn(move || {
        bounded(move || Pattern::Nk.accept(DeadlineTcp::new(peer), responder))
    });
    let result =
        bounded(move || Pattern::Nk.dial(DeadlineTcp::new(conn), generate_keypair(), wrong_remote));
    assert!(result.is_err(), "dial accepted the wrong responder key");
    assert!(
        worker.join().unwrap().is_err(),
        "accept authenticated the wrong key"
    );
}

//! Approved session lifecycle through public XX/NK APIs over real loopback TCP.
//! Fault injection belongs to the caller's transport; no private session state is used.
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use trueseal_noise::keypair::{generate_keypair, Keypair};
use trueseal_noise::{session_nk, session_xx};

const PROLOGUE: &[u8] = b"NOISE-3 adversarial boundary";
const BOUND: Duration = Duration::from_secs(5);
const CANCEL_BOUND: Duration = Duration::from_millis(250);

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
struct WriteFault {
    kind: AtomicU8,
    remaining: AtomicUsize,
    written: AtomicUsize,
    attempts: AtomicUsize,
}

impl WriteFault {
    fn arm(&self, kind: u8, remaining: usize) {
        self.remaining.store(remaining, Ordering::Release);
        self.written.store(0, Ordering::Release);
        self.attempts.store(0, Ordering::Release);
        self.kind.store(kind, Ordering::Release);
    }
}

// The caller owns the absolute deadline, including a rescue for failed assertions.
// This retains the post-handshake WouldBlock observation from #38's exact repro.
struct DeadlineTcp {
    stream: TcpStream,
    deadline: Instant,
    waiting: Option<mpsc::Sender<()>>,
    observe_waiting: Arc<AtomicBool>,
    write_fault: Arc<WriteFault>,
    read_bytes: Arc<AtomicUsize>,
    observe_after: Arc<AtomicUsize>,
    interrupt_reads: Arc<AtomicBool>,
    blocking_read: Arc<AtomicBool>,
    read_entered: Option<mpsc::Sender<()>>,
    observe_write: Arc<AtomicBool>,
    write_gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    write_waiting: Option<mpsc::Sender<()>>,
}

impl DeadlineTcp {
    fn new(stream: TcpStream) -> Self {
        stream.set_nonblocking(true).unwrap();
        Self {
            stream,
            deadline: Instant::now() + BOUND,
            waiting: None,
            observe_waiting: Arc::new(AtomicBool::new(false)),
            write_fault: Arc::new(WriteFault::default()),
            read_bytes: Arc::new(AtomicUsize::new(0)),
            observe_after: Arc::new(AtomicUsize::new(0)),
            interrupt_reads: Arc::new(AtomicBool::new(false)),
            blocking_read: Arc::new(AtomicBool::new(false)),
            read_entered: None,
            observe_write: Arc::new(AtomicBool::new(false)),
            write_gate: None,
            write_waiting: None,
        }
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            Err(io::Error::new(
                ErrorKind::TimedOut,
                "caller transport deadline expired",
            ))
        } else {
            Ok(())
        }
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        if self.blocking_read.load(Ordering::Acquire) {
            self.stream.set_nonblocking(false)?;
            self.stream.set_read_timeout(Some(BOUND))?;
            if let Some(entered) = self.read_entered.take() {
                entered.send(()).unwrap();
            }
        }
        let mut result = self.stream.read(out);
        if self.observe_waiting.load(Ordering::Acquire) {
            if let Ok(n) = result {
                self.read_bytes.fetch_add(n, Ordering::AcqRel);
            }
            if self.interrupt_reads.load(Ordering::Acquire)
                && matches!(&result, Err(e) if e.kind() == ErrorKind::WouldBlock)
            {
                result = Err(ErrorKind::Interrupted.into());
            }
        }
        if self.observe_waiting.load(Ordering::Acquire)
            && self.read_bytes.load(Ordering::Acquire) >= self.observe_after.load(Ordering::Acquire)
            && matches!(&result, Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted))
        {
            if let Some(waiting) = self.waiting.take() {
                waiting.send(()).unwrap();
            }
        }
        result
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        if self.observe_write.load(Ordering::Acquire) {
            if let Some((entered, release)) = self.write_gate.take() {
                entered.send(()).unwrap();
                release.recv_timeout(BOUND).unwrap();
            }
        }
        self.write_fault.attempts.fetch_add(1, Ordering::AcqRel);
        let kind = self.write_fault.kind.load(Ordering::Acquire);
        let remaining = self.write_fault.remaining.load(Ordering::Acquire);
        if kind != 0 && remaining == 0 {
            if kind == 3 || kind == 4 {
                if let Some(waiting) = self.write_waiting.take() {
                    waiting.send(()).unwrap();
                }
                return Err(if kind == 3 {
                    ErrorKind::WouldBlock
                } else {
                    ErrorKind::Interrupted
                }
                .into());
            }
            // A one-shot failure makes an unsafe subsequent retry observable.
            self.write_fault.kind.store(0, Ordering::Release);
            return if kind == 1 {
                Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "injected terminal write failure",
                ))
            } else {
                Ok(0)
            };
        }
        let allowed = if kind == 0 {
            bytes.len()
        } else {
            bytes.len().min(remaining)
        };
        let result = self.stream.write(&bytes[..allowed]);
        if let Ok(n) = result {
            self.write_fault.written.fetch_add(n, Ordering::AcqRel);
            if kind != 0 {
                self.write_fault.remaining.fetch_sub(n, Ordering::AcqRel);
            }
        }
        result
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

// Reused public-handshake fixture from codex/noise3-close-repro at e79282f.
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

fn terminal_write_failure_closes_session(pattern: Pattern) {
    for dial in [true, false] {
        for (kind, progress) in [(1, 0), (1, 1), (1, 7), (2, 0), (2, 7)] {
            let (conn, peer) = tcp_pair();
            let conn = DeadlineTcp::new(conn);
            let fault = conn.write_fault.clone();
            let (session, mut peer, mut transport) = connected(pattern, dial, conn, peer);
            fault.arm(kind, progress);
            let err = session.send(b"nonce already spent").unwrap_err();
            assert!(err.contains("noise: send:"), "{err}");
            assert_eq!(fault.written.load(Ordering::Acquire), progress);
            let mut prefix = vec![0; progress];
            peer.read_exact(&mut prefix).unwrap();
            // Even an authenticated peer reply must not revive a failed-write session.
            let mut reply = [0; 32];
            let n = transport.write_message(b"reply", &mut reply).unwrap();
            write_frame(&mut peer, &reply[..n]);
            let attempts = fault.attempts.load(Ordering::Acquire);
            let retry = session.send(b"must not retry");
            assert!(matches!(&retry, Err(e) if e.contains("session is closed")),
                "{pattern:?} dial={dial}, kind={kind}, progress={progress}: failed-write session accepted a retry: {retry:?}");
            assert!(session.receive().unwrap_err().contains("session is closed"));
            assert_eq!(fault.attempts.load(Ordering::Acquire), attempts);
            session.close().unwrap();
            session.close().unwrap();
        }
    }
}

#[test]
fn xx_terminal_write_failure_closes_session() {
    terminal_write_failure_closes_session(Pattern::Xx);
}

#[test]
fn nk_terminal_write_failure_closes_session() {
    terminal_write_failure_closes_session(Pattern::Nk);
}

// Exact #38 reproduction, handed off from tests/adversarial.rs at e79282f.
// Its pre-fix failure is recorded in #38 and artifact://67; not rerun to confirm.
fn close_unblocks_pending_receive(pattern: Pattern) {
    let (conn, peer) = tcp_pair();
    let rescue = conn.try_clone().unwrap();
    let mut conn = DeadlineTcp::new(conn);
    let (waiting_tx, waiting_rx) = mpsc::channel();
    conn.waiting = Some(waiting_tx);
    let observe_waiting = conn.observe_waiting.clone();
    let (session, _peer, _) = connected(pattern, true, conn, peer);
    observe_waiting.store(true, Ordering::Release);
    let session = Arc::new(session);
    let reader = session.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || done_tx.send(reader.receive()).unwrap());
    waiting_rx.recv_timeout(BOUND).unwrap();
    session.close().unwrap();
    let result = done_rx.recv_timeout(Duration::from_millis(250));
    // Always unblock and join the worker before asserting: no runaway retry loop.
    rescue.shutdown(Shutdown::Both).unwrap();
    if result.is_err() {
        done_rx.recv_timeout(BOUND).unwrap().unwrap_err();
    }
    worker.join().unwrap();
    assert!(matches!(result, Ok(Err(_))), "{pattern:?}: pending receive did not return Err after close; transport shutdown was needed");
}

// For every result, rescue and join before making assertions about cancellation.
fn finish_workers(
    rescue: &TcpStream,
    results: &mpsc::Receiver<Result<(), String>>,
    workers: Vec<thread::JoinHandle<()>>,
) -> Vec<Result<(), String>> {
    let mut received = Vec::new();
    let deadline = Instant::now() + CANCEL_BOUND;
    for _ in 0..workers.len() {
        match results.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => received.push(result),
            Err(_) => break,
        }
    }
    rescue.shutdown(Shutdown::Both).unwrap();
    for worker in workers {
        worker.join().unwrap();
    }
    received
}

fn spawn_receive(
    session: &Arc<Session>,
    done: &mpsc::Sender<Result<(), String>>,
) -> thread::JoinHandle<()> {
    let session = session.clone();
    let done = done.clone();
    thread::spawn(move || done.send(session.receive().map(|_| ())).unwrap())
}

fn close_partial_and_queued_receives(pattern: Pattern) {
    for dial in [true, false] {
        for interrupted in [false, true] {
            for progress in [0, 1, 2, 3, 17] {
                let (conn, peer) = tcp_pair();
                let rescue = conn.try_clone().unwrap();
                let mut conn = DeadlineTcp::new(conn);
                let (waiting_tx, waiting_rx) = mpsc::channel();
                conn.waiting = Some(waiting_tx);
                let observe = conn.observe_waiting.clone();
                let bytes = conn.read_bytes.clone();
                let observe_after = conn.observe_after.clone();
                let interrupt = conn.interrupt_reads.clone();
                let (session, mut peer, mut transport) = connected(pattern, dial, conn, peer);
                let session = Arc::new(session);
                let mut frame = [0; 64];
                let n = transport
                    .write_message(b"partial frame", &mut frame[2..])
                    .unwrap();
                frame[..2].copy_from_slice(&(n as u16).to_be_bytes());
                peer.write_all(&frame[..progress]).unwrap();
                // TCP delivery may lag write_all: observe the wait only after
                // the requested header/body prefix was actually consumed.
                observe_after.store(progress, Ordering::Release);
                observe.store(true, Ordering::Release);
                interrupt.store(interrupted, Ordering::Release);
                let (done_tx, done_rx) = mpsc::channel();
                let mut workers = vec![spawn_receive(&session, &done_tx)];
                waiting_rx.recv_timeout(BOUND).unwrap();
                let observed_bytes = bytes.load(Ordering::Acquire);
                for _ in 0..3 {
                    workers.push(spawn_receive(&session, &done_tx));
                }
                // With a partial frame, no receiver can complete before closure.
                let before_close = done_rx.recv_timeout(Duration::from_millis(20));
                session.close().unwrap();
                let received = finish_workers(&rescue, &done_rx, workers);
                assert!(before_close.is_err());
                assert_eq!(
                    observed_bytes, progress,
                    "{pattern:?}: partial frame boundary"
                );
                assert_eq!(
                    received.len(),
                    4,
                    "{pattern:?}: pending/queued readers needed transport shutdown"
                );
                assert!(received
                    .iter()
                    .all(|r| matches!(r, Err(e) if e.contains("session is closed"))));
                assert!(session
                    .send(b"closed")
                    .unwrap_err()
                    .contains("session is closed"));
                assert!(session.receive().unwrap_err().contains("session is closed"));
                session.close().unwrap();
            }
        }
    }
}

fn terminal_failure_rejects_concurrent_operations(pattern: Pattern) {
    for dial in [true, false] {
        for (kind, progress) in [(1, 0), (1, 7), (2, 0), (2, 7)] {
            let (conn, peer) = tcp_pair();
            let rescue = conn.try_clone().unwrap();
            let mut conn = DeadlineTcp::new(conn);
            let fault = conn.write_fault.clone();
            let observe_read = conn.observe_waiting.clone();
            let observe_write = conn.observe_write.clone();
            let (waiting_tx, waiting_rx) = mpsc::channel();
            conn.waiting = Some(waiting_tx);
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            conn.write_gate = Some((entered_tx, release_rx));
            let (session, _peer, _) = connected(pattern, dial, conn, peer);
            let session = Arc::new(session);
            observe_read.store(true, Ordering::Release);
            let (done_tx, done_rx) = mpsc::channel();
            let mut workers = vec![spawn_receive(&session, &done_tx)];
            waiting_rx.recv_timeout(BOUND).unwrap();
            fault.arm(kind, progress);
            observe_write.store(true, Ordering::Release);
            let sender = session.clone();
            let (failed_tx, failed_rx) = mpsc::channel();
            let failing = thread::spawn(move || failed_tx.send(sender.send(b"fails")).unwrap());
            entered_rx.recv_timeout(BOUND).unwrap();
            for _ in 0..3 {
                workers.push(spawn_receive(&session, &done_tx));
                let sender = session.clone();
                let done = done_tx.clone();
                workers.push(thread::spawn(move || {
                    done.send(sender.send(b"queued")).unwrap()
                }));
            }
            let before_failure = done_rx.recv_timeout(Duration::from_millis(20));
            release_tx.send(()).unwrap();
            let failure = failed_rx.recv_timeout(BOUND).unwrap();
            failing.join().unwrap();
            let received = finish_workers(&rescue, &done_rx, workers);
            assert!(before_failure.is_err());
            assert!(matches!(failure, Err(e) if e.contains("noise: send:")));
            assert_eq!(fault.written.load(Ordering::Acquire), progress);
            assert_eq!(
                received.len(),
                7,
                "{pattern:?}: terminal failure did not release operations"
            );
            assert!(received
                .iter()
                .all(|r| matches!(r, Err(e) if e.contains("session is closed"))));
        }
    }
}

fn close_cancels_send_retries(pattern: Pattern) {
    for kind in [3, 4] {
        let (conn, peer) = tcp_pair();
        let rescue = conn.try_clone().unwrap();
        let mut conn = DeadlineTcp::new(conn);
        let fault = conn.write_fault.clone();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        conn.write_waiting = Some(waiting_tx);
        let (session, _peer, _) = connected(pattern, true, conn, peer);
        let session = Arc::new(session);
        fault.arm(kind, 7);
        let sender = session.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let done = done_tx.clone();
        let mut workers = vec![thread::spawn(move || {
            done.send(sender.send(b"retry")).unwrap()
        })];
        waiting_rx.recv_timeout(BOUND).unwrap();
        let sender = session.clone();
        workers.push(thread::spawn(move || {
            done_tx.send(sender.send(b"queued")).unwrap()
        }));
        session.close().unwrap();
        let received = finish_workers(&rescue, &done_rx, workers);
        assert_eq!(received.len(), 2, "{pattern:?}: send retry ignored closure");
        assert_eq!(fault.written.load(Ordering::Acquire), 7);
        assert!(received
            .iter()
            .all(|r| matches!(r, Err(e) if e.contains("session is closed"))));
    }
}

fn blocking_read_remains_caller_owned(pattern: Pattern) {
    let (conn, peer) = tcp_pair();
    let rescue = conn.try_clone().unwrap();
    let mut conn = DeadlineTcp::new(conn);
    let blocking = conn.blocking_read.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    conn.read_entered = Some(entered_tx);
    let (session, _peer, _) = connected(pattern, true, conn, peer);
    let session = Arc::new(session);
    blocking.store(true, Ordering::Release);
    let (done_tx, done_rx) = mpsc::channel();
    let worker = spawn_receive(&session, &done_tx);
    entered_rx.recv_timeout(BOUND).unwrap();
    session.close().unwrap();
    let after_close = done_rx.recv_timeout(Duration::from_millis(50));
    // Only the caller's TCP shutdown releases the already-blocked transport call.
    rescue.shutdown(Shutdown::Both).unwrap();
    let after_shutdown = done_rx.recv_timeout(BOUND);
    worker.join().unwrap();
    assert!(
        after_close.is_err(),
        "close unexpectedly interrupted the blocking transport"
    );
    assert!(matches!(after_shutdown, Ok(Err(e)) if e.contains("session is closed")));
}

fn close_leaves_transport_caller_owned(pattern: Pattern) {
    let (conn, peer) = tcp_pair();
    let mut caller = conn.try_clone().unwrap();
    let (session, mut peer, _) = connected(pattern, true, DeadlineTcp::new(conn), peer);
    session.close().unwrap();
    caller.write_all(b"caller still owns transport").unwrap();
    let mut bytes = [0; 27];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"caller still owns transport");
}

fn real_tcp_lifecycle_smoke(pattern: Pattern) {
    // The original public real-TCP repro is the cancellation half of the smoke.
    close_unblocks_pending_receive(pattern);
    let (conn, peer) = tcp_pair();
    let mut caller = conn.try_clone().unwrap();
    let (session, mut peer, _) = connected(pattern, true, DeadlineTcp::new(conn), peer);
    // This is a native socket write failure, not the fault-injection control.
    caller.shutdown(Shutdown::Write).unwrap();
    let failure = session.send(b"native broken pipe").unwrap_err();
    assert!(failure.contains("noise: send:"), "{failure}");
    assert!(session
        .send(b"retry")
        .unwrap_err()
        .contains("session is closed"));
    assert!(session.receive().unwrap_err().contains("session is closed"));
    // Automatic closure did not shut down the transport's read half either.
    peer.write_all(b"caller read").unwrap();
    caller.set_nonblocking(false).unwrap();
    caller.set_read_timeout(Some(BOUND)).unwrap();
    let mut bytes = [0; 11];
    caller.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"caller read");
    eprintln!("{pattern:?} public real TCP smoke: pending receive cooperatively cancelled; native {failure}; later send/receive rejected; transport remains caller-owned");
}

struct CallbackTcp(TcpStream);

impl trueseal_noise::ffi::NoiseTransport for CallbackTcp {
    fn read(&self, count: u64) -> Result<Vec<u8>, trueseal_noise::ffi::NoiseError> {
        let mut bytes = vec![0; count as usize];
        (&self.0).read_exact(&mut bytes).map_err(|e| {
            trueseal_noise::ffi::NoiseError::Transport {
                message: e.to_string(),
            }
        })?;
        Ok(bytes)
    }

    fn write(&self, bytes: Vec<u8>) -> Result<(), trueseal_noise::ffi::NoiseError> {
        (&self.0)
            .write_all(&bytes)
            .map_err(|e| trueseal_noise::ffi::NoiseError::Transport {
                message: e.to_string(),
            })
    }
}

fn ffi_terminal_failure_reports_closed(pattern: Pattern) {
    use trueseal_noise::ffi::{self, NoiseError};
    let (conn, peer) = tcp_pair();
    conn.set_read_timeout(Some(BOUND)).unwrap();
    conn.set_write_timeout(Some(BOUND)).unwrap();
    let caller = conn.try_clone().unwrap();
    let conn = Arc::new(CallbackTcp(conn));
    let peer = Arc::new(CallbackTcp(peer));
    let errors = match pattern {
        Pattern::Xx => {
            let responder =
                thread::spawn(move || ffi::accept_xx(peer, ffi::generate_keypair(), PROLOGUE));
            let session = ffi::dial_xx(conn, ffi::generate_keypair(), PROLOGUE).unwrap();
            let _peer = responder.join().unwrap().unwrap();
            caller.shutdown(Shutdown::Write).unwrap();
            (
                session.send(b"fails").unwrap_err(),
                session.send(b"retry").unwrap_err(),
                session.receive().unwrap_err(),
            )
        }
        Pattern::Nk => {
            let key = ffi::generate_keypair();
            let remote = key.public_key.clone();
            let responder = thread::spawn(move || ffi::accept_nk(peer, key, PROLOGUE));
            let session = ffi::dial_nk(conn, ffi::generate_keypair(), remote, PROLOGUE).unwrap();
            let _peer = responder.join().unwrap().unwrap();
            caller.shutdown(Shutdown::Write).unwrap();
            (
                session.send(b"fails").unwrap_err(),
                session.send(b"retry").unwrap_err(),
                session.receive().unwrap_err(),
            )
        }
    };
    assert!(matches!(errors.0, NoiseError::Transport { .. }));
    assert!(matches!(errors.1, NoiseError::Closed {}));
    assert!(matches!(errors.2, NoiseError::Closed {}));
}

macro_rules! lifecycle_tests {
    ($module:ident, $pattern:expr) => {
        mod $module {
            use super::*;
            #[test]
            fn close_unblocks_pending_receive() {
                super::close_unblocks_pending_receive($pattern);
            }
            #[test]
            fn close_partial_and_queued_receives() {
                super::close_partial_and_queued_receives($pattern);
            }
            #[test]
            fn terminal_failure_rejects_concurrent_operations() {
                super::terminal_failure_rejects_concurrent_operations($pattern);
            }
            #[test]
            fn close_cancels_send_retries() {
                super::close_cancels_send_retries($pattern);
            }
            #[test]
            fn blocking_read_remains_caller_owned() {
                super::blocking_read_remains_caller_owned($pattern);
            }
            #[test]
            fn close_leaves_transport_caller_owned() {
                super::close_leaves_transport_caller_owned($pattern);
            }
            #[test]
            fn real_tcp_lifecycle_smoke() {
                super::real_tcp_lifecycle_smoke($pattern);
            }
            #[test]
            fn ffi_terminal_failure_reports_closed() {
                super::ffi_terminal_failure_reports_closed($pattern);
            }
        }
    };
}

lifecycle_tests!(xx, Pattern::Xx);
lifecycle_tests!(nk, Pattern::Nk);

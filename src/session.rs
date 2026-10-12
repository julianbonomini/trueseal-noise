use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use crate::framing::MAX_PLAINTEXT_SIZE;

// ── RetryConn ─────────────────────────────────────────────────────────────────

/// Read+Write adapter that retries on WouldBlock/Interrupted, sleeping briefly.
/// Used during the handshake phase so transports that return WouldBlock when
/// data is not yet available work correctly with read_exact.
pub(crate) struct RetryConn<T: Read + Write>(pub(crate) T);

impl<T: Read + Write> Read for RetryConn<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.read(buf) {
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
                other => return other,
            }
        }
    }
}

impl<T: Read + Write> Write for RetryConn<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            match self.0.write(buf) {
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
                other => return other,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

// ── SessionInner ──────────────────────────────────────────────────────────────

/// Shared post-handshake state used by both `session_xx::Session` and
/// `session_nk::Session`. Holds the transport, a snow TransportState, and
/// the closed flag.
///
/// snow::TransportState requires &mut self — all crypto ops are serialised
/// through a single Mutex. send and receive acquire the transport mutex
/// separately from the conn mutex so concurrent callers can at least overlap
/// I/O waits.
pub(crate) struct SessionInner<T: Read + Write + Send> {
    conn: Arc<Mutex<T>>,
    transport: Mutex<snow::TransportState>,
    closed: Mutex<bool>,
}

impl<T: Read + Write + Send> SessionInner<T> {
    pub(crate) fn new(conn: T, transport: snow::TransportState) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            transport: Mutex::new(transport),
            closed: Mutex::new(false),
        }
    }

    /// Read exactly `n` bytes, releasing the conn mutex between read() calls
    /// so concurrent send() can interleave.
    ///
    /// The guard is bound to a `let` so it drops at the `;` — before the
    /// match — ensuring the lock is never held across the WouldBlock sleep.
    pub(crate) fn read_exact_interruptible(&self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let mut filled = 0;
        while filled < n {
            // Lock, read, unlock (guard drops at `;` before match).
            let result = self
                .conn
                .lock()
                .map_err(|_| io::Error::other("noise: session poisoned"))?
                .read(&mut buf[filled..]);
            match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(k) => filled += k,
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    // Sleep without holding the lock so concurrent send() can proceed.
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(buf)
    }

    /// Encrypts payload and writes it to the transport with a 2-byte
    /// big-endian length prefix.
    pub(crate) fn send(&self, payload: &[u8]) -> Result<(), String> {
        if payload.len() > MAX_PLAINTEXT_SIZE {
            return Err(format!(
                "noise: payload exceeds maximum message size ({} > {})",
                payload.len(),
                MAX_PLAINTEXT_SIZE
            ));
        }
        if *self
            .closed
            .lock()
            .map_err(|_| "noise: session poisoned".to_string())?
        {
            return Err("noise: session is closed".to_string());
        }
        // Allocate ciphertext buffer: plaintext + 16-byte AEAD tag.
        let mut ciphertext = vec![0u8; payload.len() + 16];
        let len = self
            .transport
            .lock()
            .map_err(|_| "noise: session poisoned".to_string())?
            .write_message(payload, &mut ciphertext)
            .map_err(|e| format!("noise: encrypt: {:?}", e))?;
        let mut framed = Vec::with_capacity(2 + len);
        framed.extend_from_slice(&(len as u16).to_be_bytes());
        framed.extend_from_slice(&ciphertext[..len]);
        self.conn
            .lock()
            .map_err(|_| "noise: session poisoned".to_string())?
            .write_all(&framed)
            .map_err(|e| format!("noise: send: {}", e))
    }

    /// Reads one framed message from the transport, decrypts it, and returns
    /// the plaintext.
    pub(crate) fn receive(&self) -> Result<Vec<u8>, String> {
        if *self
            .closed
            .lock()
            .map_err(|_| "noise: session poisoned".to_string())?
        {
            return Err("noise: session is closed".to_string());
        }
        let header = self
            .read_exact_interruptible(2)
            .map_err(|e| format!("noise: receive header: {}", e))?;
        let size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let ciphertext = self
            .read_exact_interruptible(size)
            .map_err(|e| format!("noise: receive body: {}", e))?;
        let mut plaintext = vec![0u8; size];
        let len = self
            .transport
            .lock()
            .map_err(|_| "noise: session poisoned".to_string())?
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| format!("noise: decrypt: {:?}", e))?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Closes the session. Subsequent send/receive return errors.
    pub(crate) fn close(&self) -> io::Result<()> {
        *self
            .closed
            .lock()
            .map_err(|_| io::Error::other("noise: session poisoned"))? = true;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{mem_pipe_pair, MemPipe, SlowWriter};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    const SENDERS: usize = 8;
    const PER_SENDER: usize = 40;

    /// Runs a handshake for `pattern` directly through snow and returns
    /// (initiator transport, responder transport). Building the sessions here
    /// keeps these tests independent of the public dial/accept signatures.
    fn transports(pattern: &str) -> (snow::TransportState, snow::TransportState) {
        let params: snow::params::NoiseParams = pattern.parse().unwrap();
        let i_key = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let r_key = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let mut ib = snow::Builder::new(params.clone())
            .local_private_key(&i_key.private)
            .unwrap();
        if pattern.contains("_NK_") {
            ib = ib.remote_public_key(&r_key.public).unwrap();
        }
        let mut i = ib.build_initiator().unwrap();
        let mut r = snow::Builder::new(params)
            .local_private_key(&r_key.private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; 65535];
        let mut initiator_turn = true;
        while !(i.is_handshake_finished() && r.is_handshake_finished()) {
            let (w, rd) = if initiator_turn {
                (&mut i, &mut r)
            } else {
                (&mut r, &mut i)
            };
            let len = w.write_message(&[], &mut buf).unwrap();
            rd.read_message(&buf[..len], &mut out).unwrap();
            initiator_turn = !initiator_turn;
        }
        (
            i.into_transport_mode().unwrap(),
            r.into_transport_mode().unwrap(),
        )
    }

    type Pair = (
        Arc<SessionInner<SlowWriter<MemPipe>>>,
        Arc<SessionInner<SlowWriter<MemPipe>>>,
    );

    fn session_pair(pattern: &str, delay: Duration) -> Pair {
        let (i_t, r_t) = transports(pattern);
        let (a, b) = mem_pipe_pair();
        (
            Arc::new(SessionInner::new(SlowWriter { inner: a, delay }, i_t)),
            Arc::new(SessionInner::new(SlowWriter { inner: b, delay }, r_t)),
        )
    }

    fn payload(sender: usize, seq: usize) -> Vec<u8> {
        format!("{sender}:{seq}").into_bytes()
    }

    fn parse(msg: &[u8]) -> (usize, usize) {
        let s = std::str::from_utf8(msg).unwrap();
        let (a, b) = s.split_once(':').unwrap();
        (a.parse().unwrap(), b.parse().unwrap())
    }

    /// Spawns SENDERS threads that each send PER_SENDER frames on `tx`.
    fn spawn_senders(
        tx: &Arc<SessionInner<SlowWriter<MemPipe>>>,
    ) -> Vec<std::thread::JoinHandle<()>> {
        (0..SENDERS)
            .map(|s| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for n in 0..PER_SENDER {
                        tx.send(&payload(s, n)).expect("send failed");
                    }
                })
            })
            .collect()
    }

    /// Many threads send on one session; the peer must decrypt every frame
    /// and see each sender's frames in that sender's order.
    fn concurrent_sends_keep_nonce_order(pattern: &str) {
        let (tx, rx) = session_pair(pattern, Duration::from_micros(200));
        let senders = spawn_senders(&tx);

        let mut next: HashMap<usize, usize> = HashMap::new();
        for i in 0..SENDERS * PER_SENDER {
            let msg = rx
                .receive()
                .unwrap_or_else(|e| panic!("{pattern}: frame {i} failed: {e}"));
            let (s, n) = parse(&msg);
            let expected = next.entry(s).or_insert(0);
            assert_eq!(n, *expected, "{pattern}: sender {s} out of order");
            *expected += 1;
        }
        for h in senders {
            h.join().unwrap();
        }
        assert!(next.values().all(|&n| n == PER_SENDER));
    }

    #[test]
    fn concurrent_sends_keep_nonce_order_xx() {
        concurrent_sends_keep_nonce_order("Noise_XX_25519_ChaChaPoly_BLAKE2s");
    }

    #[test]
    fn concurrent_sends_keep_nonce_order_nk() {
        concurrent_sends_keep_nonce_order("Noise_NK_25519_ChaChaPoly_BLAKE2s");
    }

    /// Many threads receive on one session while a single thread sends on
    /// the peer, so any failure comes from the receive side. Every frame must
    /// decrypt and be delivered exactly once.
    fn concurrent_receives_get_whole_frames(pattern: &str) {
        let (tx, rx) = session_pair(pattern, Duration::from_micros(50));
        let sender = std::thread::spawn(move || {
            for s in 0..SENDERS {
                for n in 0..PER_SENDER {
                    tx.send(&payload(s, n)).expect("send failed");
                }
            }
        });

        // Receivers claim receive calls from a shared budget so the total
        // equals the number of frames sent. Results go over a channel with a
        // timeout: a broken receive path can desync the stream and leave
        // other receivers waiting forever, and the test must fail, not hang.
        const RECEIVERS: usize = 4;
        let total = SENDERS * PER_SENDER;
        let claimed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (results_tx, results_rx) = std::sync::mpsc::channel();
        for _ in 0..RECEIVERS {
            let rx = rx.clone();
            let claimed = claimed.clone();
            let results_tx = results_tx.clone();
            std::thread::spawn(move || {
                while claimed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < total {
                    let result = rx.receive();
                    let failed = result.is_err();
                    if results_tx.send(result).is_err() || failed {
                        return;
                    }
                }
            });
        }

        let mut seen: Vec<(usize, usize)> = (0..total)
            .map(|i| match results_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(msg)) => parse(&msg),
                Ok(Err(e)) => panic!("{pattern}: frame {i} failed: {e}"),
                Err(_) => panic!("{pattern}: timed out after {i} frames"),
            })
            .collect();
        sender.join().unwrap();
        seen.sort_unstable();
        let expected: Vec<_> = (0..SENDERS)
            .flat_map(|s| (0..PER_SENDER).map(move |n| (s, n)))
            .collect();
        assert_eq!(seen, expected, "{pattern}: frames lost or duplicated");
    }

    #[test]
    fn concurrent_receives_get_whole_frames_xx() {
        concurrent_receives_get_whole_frames("Noise_XX_25519_ChaChaPoly_BLAKE2s");
    }

    #[test]
    fn concurrent_receives_get_whole_frames_nk() {
        concurrent_receives_get_whole_frames("Noise_NK_25519_ChaChaPoly_BLAKE2s");
    }
}

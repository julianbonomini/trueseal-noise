use std::io::{self, Read, Write};

use crate::{
    framing::{read_frame, write_frame},
    keypair::Keypair,
    session::{RetryConn, SessionInner},
};

/// A fully negotiated, bidirectional encrypted channel produced by the NK
/// Handshake Pattern. Sessions are not resumable after close.
///
/// `Session` is `Sync`: share it with `Arc` and call it from many threads.
/// Concurrent `send` calls are serialised, so frames reach the wire in nonce
/// order. Concurrent `receive` calls are serialised, so each returns one
/// whole frame. One `send` can overlap one `receive` only if the transport's
/// `read()` returns `WouldBlock` (or data) rather than blocking; a blocking
/// `read()` holds the connection and stalls `send` until data arrives.
///
/// The NK pattern is anonymous for the Initiator — the Responder never
/// learns the Initiator's static key. `remote_public_key()` is therefore
/// absent from this type entirely.
pub struct Session<T: Read + Write + Send> {
    inner: SessionInner<T>,
}

impl<T: Read + Write + Send> Session<T> {
    fn new(conn: T, transport: snow::TransportState) -> Self {
        Self {
            inner: SessionInner::new(conn, transport),
        }
    }

    /// Encrypts payload and writes it to the transport with a 2-byte
    /// big-endian length prefix.
    /// A terminal write failure after nonce advancement closes the session;
    /// later/queued operations reject. WouldBlock/Interrupted remain retryable.
    pub fn send(&self, payload: &[u8]) -> Result<(), String> {
        self.inner.send(payload)
    }

    /// Reads one framed message from the transport and decrypts it.
    /// Pending nonblocking reads, including partial frames, return an error
    /// when they next observe closure. Blocking I/O remains caller-owned.
    pub fn receive(&self) -> Result<Vec<u8>, String> {
        self.inner.receive()
    }

    /// Marks the session unusable; queued operations and retry loops reject
    /// when they observe closure. Does not shut down the caller's transport
    /// or interrupt already-blocked I/O. Sessions are not resumable.
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

// ── dial / accept ─────────────────────────────────────────────────────────────

/// Performs the NK handshake as the Initiator over conn.
/// `remote_static` is the Responder's known static public key — the Initiator
/// must have it before calling dial. Returns a Session on success.
///
/// `prologue` is mixed into the handshake hash. Both peers must pass
/// byte-identical prologues or the handshake fails on both sides. The library
/// only binds the bytes: the caller decides what they are (for example a
/// plaintext version prefix it has already exchanged) and checks them.
/// Pass an empty slice for no prologue.
pub fn dial<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    remote_static: [u8; 32],
    prologue: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, Some(remote_static), prologue, None)
}

/// Performs the NK handshake as the Responder over conn using the provided
/// Keypair. Returns a Session on success.
///
/// `prologue` must be byte-identical to the Initiator's; see [`dial`].
pub fn accept<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, None, prologue, None)
}

/// Test-only `dial` with a fixed ephemeral key, for spec test vectors.
#[cfg(test)]
pub(crate) fn dial_with_fixed_ephemeral<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    remote_static: [u8; 32],
    prologue: &[u8],
    ephemeral: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(
        conn,
        keypair,
        Some(remote_static),
        prologue,
        Some(ephemeral),
    )
}

/// Test-only `accept` with a fixed ephemeral key, for spec test vectors.
#[cfg(test)]
pub(crate) fn accept_with_fixed_ephemeral<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
    ephemeral: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, None, prologue, Some(ephemeral))
}

fn do_handshake<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    remote_static: Option<[u8; 32]>,
    prologue: &[u8],
    fixed_ephemeral: Option<&[u8]>,
) -> Result<Session<T>, String> {
    // Bind key bytes to locals with sufficient lifetime for the builder borrows.
    let priv_key = keypair.private();
    let rs_buf: Option<[u8; 32]> = remote_static;

    let mut builder = snow::Builder::new(
        "Noise_NK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| format!("noise: bad params: {:?}", e))?,
    )
    .prologue(prologue)
    .map_err(|e| format!("noise: set prologue: {:?}", e))?
    .local_private_key(&priv_key)
    .map_err(|e| format!("noise: set local key: {:?}", e))?;

    if let Some(eph) = fixed_ephemeral {
        builder = builder.fixed_ephemeral_key_for_testing_only(eph);
    }

    if let Some(ref rs) = rs_buf {
        builder = builder
            .remote_public_key(rs)
            .map_err(|e| format!("noise: set remote key: {:?}", e))?;
    }

    let mut hs = if remote_static.is_some() {
        builder
            .build_initiator()
            .map_err(|e| format!("noise: build initiator: {:?}", e))?
    } else {
        builder
            .build_responder()
            .map_err(|e| format!("noise: build responder: {:?}", e))?
    };

    let mut rc = RetryConn(conn);
    let mut buf = vec![0u8; 65535];

    if remote_static.is_some() {
        // Initiator: -> e, es
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg0: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg0: {}", e))?;

        // <- e, ee
        let msg1 = read_frame(&mut rc).map_err(|e| format!("noise: read msg1: {}", e))?;
        hs.read_message(&msg1, &mut buf)
            .map_err(|e| format!("noise: read msg1: {:?}", e))?;
    } else {
        // Responder: <- e, es
        let msg0 = read_frame(&mut rc).map_err(|e| format!("noise: read msg0: {}", e))?;
        hs.read_message(&msg0, &mut buf)
            .map_err(|e| format!("noise: read msg0: {:?}", e))?;

        // -> e, ee
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg1: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg1: {}", e))?;
    }

    let transport = hs
        .into_transport_mode()
        .map_err(|e| format!("noise: into_transport_mode: {:?}", e))?;

    Ok(Session::new(rc.0, transport))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;
    use crate::test_helpers::{mem_pipe_pair, tcp_pair};

    const PROLOGUE: &[u8] = b"trueseal-noise test prologue";

    /// Runs dial and accept with the given prologues over a loopback TCP pair
    /// and returns both results.
    fn handshake_with_prologues(
        i_prologue: &'static [u8],
        r_prologue: &'static [u8],
    ) -> (
        Result<Session<std::net::TcpStream>, String>,
        Result<Session<std::net::TcpStream>, String>,
    ) {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = tcp_pair();
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp, r_prologue));
        let i_result = dial(i_conn, i_kp, r_pub, i_prologue);
        let r_result = r_handle.join().unwrap();
        (i_result, r_result)
    }

    #[test]
    fn matching_prologue_completes_handshake() {
        let (i, r) = handshake_with_prologues(b"v1 prefix", b"v1 prefix");
        let i = i.expect("dial failed");
        let r = r.expect("accept failed");
        i.send(b"bound").expect("send failed");
        assert_eq!(r.receive().expect("receive failed"), b"bound");
        r.send(b"back").expect("send failed");
        assert_eq!(i.receive().expect("receive failed"), b"back");
    }

    #[test]
    fn empty_prologue_on_both_sides_completes_handshake() {
        let (i, r) = handshake_with_prologues(b"", b"");
        assert!(i.is_ok() && r.is_ok());
    }

    #[test]
    fn one_byte_prologue_mismatch_fails_on_both_sides() {
        let (i, r) = handshake_with_prologues(b"v1 prefix", b"v2 prefix");
        let i_err = i.err().expect("dial must fail on prologue mismatch");
        let r_err = r.err().expect("accept must fail on prologue mismatch");
        // msg0 is authenticated against the Initiator's transcript, so the
        // Responder detects the mismatch cryptographically and aborts; the
        // Initiator then sees the connection close before msg1.
        assert!(
            r_err.contains("read msg0"),
            "unexpected accept error: {r_err}"
        );
        assert!(i_err.contains("msg1"), "unexpected dial error: {i_err}");
    }

    #[test]
    fn prologue_length_mismatch_fails_on_both_sides() {
        let (i, r) = handshake_with_prologues(b"v1", b"v1\0");
        assert!(i.is_err(), "dial must fail");
        assert!(r.is_err(), "accept must fail");
    }

    #[test]
    fn dial_accept_complete() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, r_pub, PROLOGUE).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        i_session.send(b"hello nk").expect("send failed");
        let msg = r_session.receive().expect("receive failed");
        assert_eq!(msg, b"hello nk");
    }

    #[test]
    fn responder_sends_to_initiator() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, r_pub, PROLOGUE).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        r_session.send(b"pong nk").expect("send failed");
        let msg = i_session.receive().expect("receive failed");
        assert_eq!(msg, b"pong nk");
    }

    #[test]
    fn send_oversize_payload_fails() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, r_pub, PROLOGUE).expect("dial failed");

        assert!(i_session.send(&vec![0u8; 65536]).is_err());
    }

    #[test]
    fn close_rejects_subsequent_send() {
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let i_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, r_pub, PROLOGUE).expect("dial failed");

        i_session.close().expect("close failed");
        assert!(i_session.send(b"after close").is_err());
    }
}

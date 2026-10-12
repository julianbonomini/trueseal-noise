use std::io::{self, Read, Write};

use crate::{
    framing::{read_frame, write_frame},
    keypair::Keypair,
    session::{RetryConn, SessionInner},
};

/// A fully negotiated, bidirectional encrypted channel produced by the XX
/// Handshake Pattern. Sessions are not resumable after close.
///
/// `Session` is `Sync`: share it with `Arc` and call it from many threads.
/// Concurrent `send` calls are serialised, so frames reach the wire in nonce
/// order. Concurrent `receive` calls are serialised, so each returns one
/// whole frame. One `send` can overlap one `receive` only if the transport's
/// `read()` returns `WouldBlock` (or data) rather than blocking; a blocking
/// `read()` holds the connection and stalls `send` until data arrives.
///
/// `remote_public_key()` returns the authenticated static public key of the
/// remote peer unconditionally — mutual authentication is guaranteed by XX.
pub struct Session<T: Read + Write + Send> {
    inner: SessionInner<T>,
    remote_pub_key: [u8; 32],
}

impl<T: Read + Write + Send> Session<T> {
    fn new(conn: T, transport: snow::TransportState, remote_pub_key: [u8; 32]) -> Self {
        Self {
            inner: SessionInner::new(conn, transport),
            remote_pub_key,
        }
    }

    /// Encrypts payload and writes it to the transport with a 2-byte
    /// big-endian length prefix.
    pub fn send(&self, payload: &[u8]) -> Result<(), String> {
        self.inner.send(payload)
    }

    /// Reads one framed message from the transport and decrypts it.
    pub fn receive(&self) -> Result<Vec<u8>, String> {
        self.inner.receive()
    }

    /// Returns the authenticated static public key of the remote peer,
    /// established during the XX handshake. Trust policy is the caller's
    /// responsibility.
    pub fn remote_public_key(&self) -> [u8; 32] {
        self.remote_pub_key
    }

    /// Closes the session. Subsequent send/receive return errors.
    /// Sessions are not resumable after close.
    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}

// ── dial / accept ─────────────────────────────────────────────────────────────

/// Performs the XX handshake as the Initiator over conn using the provided
/// Keypair. Returns a Session on success or an error string.
///
/// `prologue` is mixed into the handshake hash. Both peers must pass
/// byte-identical prologues or the handshake fails on both sides. The library
/// only binds the bytes: the caller decides what they are (for example a
/// plaintext version prefix it has already exchanged) and checks them.
/// Pass an empty slice for no prologue.
pub fn dial<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, prologue, true, None)
}

/// Performs the XX handshake as the Responder over conn using the provided
/// Keypair. Returns a Session on success or an error string.
///
/// `prologue` must be byte-identical to the Initiator's; see [`dial`].
pub fn accept<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, prologue, false, None)
}

/// Test-only `dial` with a fixed ephemeral key, for spec test vectors.
#[cfg(test)]
pub(crate) fn dial_with_fixed_ephemeral<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
    ephemeral: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, prologue, true, Some(ephemeral))
}

/// Test-only `accept` with a fixed ephemeral key, for spec test vectors.
#[cfg(test)]
pub(crate) fn accept_with_fixed_ephemeral<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
    ephemeral: &[u8],
) -> Result<Session<T>, String> {
    do_handshake(conn, keypair, prologue, false, Some(ephemeral))
}

fn do_handshake<T: Read + Write + Send>(
    conn: T,
    keypair: Keypair,
    prologue: &[u8],
    initiator: bool,
    fixed_ephemeral: Option<&[u8]>,
) -> Result<Session<T>, String> {
    let priv_key = keypair.private();
    let mut builder = snow::Builder::new(
        "Noise_XX_25519_ChaChaPoly_BLAKE2s"
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

    let mut hs = if initiator {
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

    if initiator {
        // -> e
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg0: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg0: {}", e))?;

        // <- e, ee, s, es
        let msg1 = read_frame(&mut rc).map_err(|e| format!("noise: read msg1: {}", e))?;
        hs.read_message(&msg1, &mut buf)
            .map_err(|e| format!("noise: read msg1: {:?}", e))?;

        // -> s, se
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg2: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg2: {}", e))?;
    } else {
        // <- e
        let msg0 = read_frame(&mut rc).map_err(|e| format!("noise: read msg0: {}", e))?;
        hs.read_message(&msg0, &mut buf)
            .map_err(|e| format!("noise: read msg0: {:?}", e))?;

        // -> e, ee, s, es
        let len = hs
            .write_message(&[], &mut buf)
            .map_err(|e| format!("noise: write msg1: {:?}", e))?;
        write_frame(&mut rc, &buf[..len]).map_err(|e| format!("noise: frame msg1: {}", e))?;

        // <- s, se
        let msg2 = read_frame(&mut rc).map_err(|e| format!("noise: read msg2: {}", e))?;
        hs.read_message(&msg2, &mut buf)
            .map_err(|e| format!("noise: read msg2: {:?}", e))?;
    }

    let remote_static = hs
        .get_remote_static()
        .ok_or_else(|| "noise: no remote static after XX handshake".to_string())?;
    let remote_pub_key: [u8; 32] = remote_static
        .try_into()
        .map_err(|_| "noise: remote static key is not 32 bytes".to_string())?;

    let transport = hs
        .into_transport_mode()
        .map_err(|e| format!("noise: into_transport_mode: {:?}", e))?;

    Ok(Session::new(rc.0, transport, remote_pub_key))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate_keypair;
    use crate::test_helpers::{mem_pipe_pair, tcp_pair};
    use std::sync::Arc;

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
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = tcp_pair();
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp, r_prologue));
        let i_result = dial(i_conn, i_kp, i_prologue);
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
        // The Initiator is the first to decrypt a message authenticated
        // against the Responder's transcript (msg1), so it detects the
        // mismatch cryptographically; the Responder then sees the
        // connection close before msg2.
        assert!(
            i_err.contains("read msg1"),
            "unexpected dial error: {i_err}"
        );
        assert!(r_err.contains("msg2"), "unexpected accept error: {r_err}");
    }

    #[test]
    fn prologue_length_mismatch_fails_on_both_sides() {
        let (i, r) = handshake_with_prologues(b"v1", b"v1\0");
        assert!(i.is_err(), "dial must fail");
        assert!(r.is_err(), "accept must fail");
    }

    #[test]
    fn dial_accept_complete() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, PROLOGUE).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        i_session.send(b"hello").expect("send failed");
        let msg = r_session.receive().expect("receive failed");
        assert_eq!(msg, b"hello");
    }

    #[test]
    fn responder_sends_to_initiator() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, PROLOGUE).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        r_session.send(b"pong").expect("send failed");
        let msg = i_session.receive().expect("receive failed");
        assert_eq!(msg, b"pong");
    }

    #[test]
    fn remote_public_key_is_correct() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let i_pub = i_kp.public_key;
        let r_pub = r_kp.public_key;
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, PROLOGUE).expect("dial failed");
        let r_session = r_handle.join().unwrap().expect("accept failed");

        assert_eq!(i_session.remote_public_key(), r_pub);
        assert_eq!(r_session.remote_public_key(), i_pub);
    }

    #[test]
    fn send_oversize_payload_fails() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, PROLOGUE).expect("dial failed");

        assert!(i_session.send(&vec![0u8; 65536]).is_err());
    }

    #[test]
    fn close_rejects_subsequent_send() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let _r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = dial(i_conn, i_kp, PROLOGUE).expect("dial failed");

        i_session.close().expect("close failed");
        assert!(i_session.send(b"after close").is_err());
    }

    #[test]
    fn concurrent_send_and_receive_do_not_deadlock() {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let (i_conn, r_conn) = mem_pipe_pair();

        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let r_handle = std::thread::spawn(move || accept(r_conn, r_kp2, PROLOGUE));
        let i_session = Arc::new(dial(i_conn, i_kp, PROLOGUE).expect("dial failed"));
        let r_session = Arc::new(r_handle.join().unwrap().expect("accept failed"));

        let r_sess_clone = r_session.clone();
        let recv_handle = std::thread::spawn(move || r_sess_clone.receive());

        i_session
            .send(b"concurrent")
            .expect("send must not deadlock");
        let msg = recv_handle.join().unwrap().expect("receive failed");
        assert_eq!(msg, b"concurrent");
    }
}

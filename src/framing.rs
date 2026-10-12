use std::io::{self, Read, Write};

/// Largest frame body: the length prefix is a u16, so 65,535 bytes.
pub(crate) const MAX_FRAME_SIZE: usize = u16::MAX as usize;

/// ChaChaPoly AEAD tag appended to every transport message.
pub(crate) const AEAD_TAG_SIZE: usize = 16;

/// Largest plaintext `send` accepts: 65,535-byte frame minus the 16-byte AEAD
/// tag, so 65,519 bytes. Larger payloads are rejected, never split across
/// frames.
///
/// trueseal-sync derives its Envelope limit and its 61,440-byte Protocol Size
/// Limit from this value (trueseal-sync ADR-0025). Raising it means widening
/// the length prefix, which is a Transport Version change.
pub const MAX_PLAINTEXT_SIZE: usize = MAX_FRAME_SIZE - AEAD_TAG_SIZE;

/// Writes data to w with a 2-byte big-endian length prefix.
pub(crate) fn write_frame(w: &mut dyn Write, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("noise: frame too large: {} bytes", data.len()),
        ));
    }
    let len = data.len() as u16;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    Ok(())
}

/// Reads a 2-byte big-endian length prefix then the body from r.
pub(crate) fn read_frame(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    r.read_exact(&mut header)?;
    let size = u16::from_be_bytes(header) as usize;
    let mut body = vec![0u8; size];
    r.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::{generate_keypair, Keypair};
    use crate::test_helpers::{mem_pipe_pair, MemPipe};
    use crate::{session_nk, session_xx};

    /// The documented numbers (README "Limits", CONTEXT.md "Framing",
    /// trueseal-sync ADR-0025). Literals on purpose: changing the ceiling
    /// must fail this test.
    #[test]
    fn size_constants_match_documented_values() {
        assert_eq!(MAX_FRAME_SIZE, 65_535);
        assert_eq!(AEAD_TAG_SIZE, 16);
        assert_eq!(MAX_PLAINTEXT_SIZE, 65_519);
    }

    /// Non-uniform payload so truncation or reordering would be caught.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn xx_pair() -> (session_xx::Session<MemPipe>, session_xx::Session<MemPipe>) {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let r_kp2 = Keypair::new(r_kp.private(), r_kp.public_key);
        let (i_conn, r_conn) = mem_pipe_pair();
        let r_handle = std::thread::spawn(move || session_xx::accept(r_conn, r_kp2, b""));
        let i = session_xx::dial(i_conn, i_kp, b"").expect("dial failed");
        let r = r_handle.join().unwrap().expect("accept failed");
        (i, r)
    }

    fn nk_pair() -> (session_nk::Session<MemPipe>, session_nk::Session<MemPipe>) {
        let i_kp = generate_keypair();
        let r_kp = generate_keypair();
        let r_pub = r_kp.public_key;
        let r_kp2 = Keypair::new(r_kp.private(), r_pub);
        let (i_conn, r_conn) = mem_pipe_pair();
        let r_handle = std::thread::spawn(move || session_nk::accept(r_conn, r_kp2, b""));
        let i = session_nk::dial(i_conn, i_kp, r_pub, b"").expect("dial failed");
        let r = r_handle.join().unwrap().expect("accept failed");
        (i, r)
    }

    #[test]
    fn xx_send_at_ceiling_arrives_intact_both_directions() {
        let (i, r) = xx_pair();
        let msg = payload(65_519);

        i.send(&msg).expect("send of 65,519 bytes failed");
        assert_eq!(r.receive().expect("receive failed"), msg);

        r.send(&msg).expect("send of 65,519 bytes failed");
        assert_eq!(i.receive().expect("receive failed"), msg);
    }

    #[test]
    fn xx_send_one_byte_over_ceiling_fails_and_session_survives() {
        let (i, r) = xx_pair();

        let err = i.send(&payload(65_520)).unwrap_err();
        assert!(err.contains("65520 > 65519"), "unexpected error: {err}");

        // Rejection happens before encryption, so nothing hits the wire and
        // the nonce does not advance.
        i.send(b"after").expect("send after rejection failed");
        assert_eq!(r.receive().expect("receive failed"), b"after");
    }

    #[test]
    fn nk_send_at_ceiling_arrives_intact_both_directions() {
        let (i, r) = nk_pair();
        let msg = payload(65_519);

        i.send(&msg).expect("send of 65,519 bytes failed");
        assert_eq!(r.receive().expect("receive failed"), msg);

        r.send(&msg).expect("send of 65,519 bytes failed");
        assert_eq!(i.receive().expect("receive failed"), msg);
    }

    #[test]
    fn nk_send_one_byte_over_ceiling_fails_and_session_survives() {
        let (i, r) = nk_pair();

        let err = i.send(&payload(65_520)).unwrap_err();
        assert!(err.contains("65520 > 65519"), "unexpected error: {err}");

        i.send(b"after").expect("send after rejection failed");
        assert_eq!(r.receive().expect("receive failed"), b"after");
    }

    #[test]
    fn write_frame_accepts_ceiling_and_rejects_one_over() {
        let mut out = Vec::new();
        write_frame(&mut out, &vec![0u8; 65_535]).expect("65,535-byte frame rejected");
        assert_eq!(&out[..2], &[0xff, 0xff]);
        assert_eq!(out.len(), 2 + 65_535);

        let err = write_frame(&mut Vec::new(), &vec![0u8; 65_536]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

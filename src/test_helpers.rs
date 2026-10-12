/// Shared test helpers for session integration tests.
/// Available to all modules in the crate under #[cfg(test)].
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

/// In-memory bidirectional pipe for testing.
///
/// read() returns WouldBlock immediately when empty so that
/// SessionInner::read_exact_interruptible() releases the conn mutex between
/// retries, allowing concurrent send() to proceed without deadlock.
pub(crate) struct MemPipe {
    pub(crate) read_buf: Arc<Mutex<Vec<u8>>>,
    pub(crate) write_buf: Arc<Mutex<Vec<u8>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for MemPipe {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl Read for MemPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rb = self.read_buf.lock().unwrap();
        if !rb.is_empty() {
            let n = buf.len().min(rb.len());
            buf[..n].copy_from_slice(&rb[..n]);
            rb.drain(..n);
            return Ok(n);
        }
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(0);
        }
        Err(io::Error::new(ErrorKind::WouldBlock, "buffer empty"))
    }
}

impl Write for MemPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns a pair of connected MemPipes: writes to A appear as reads on B
/// and vice versa.
pub(crate) fn mem_pipe_pair() -> (MemPipe, MemPipe) {
    let ab = Arc::new(Mutex::new(Vec::new()));
    let ba = Arc::new(Mutex::new(Vec::new()));
    let a_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        MemPipe {
            read_buf: ba.clone(),
            write_buf: ab.clone(),
            closed: b_closed.clone(),
        },
        MemPipe {
            read_buf: ab.clone(),
            write_buf: ba.clone(),
            closed: a_closed.clone(),
        },
    )
}

/// Returns a connected pair of loopback TCP streams.
///
/// Unlike `mem_pipe_pair`, dropping one end makes reads on the other end
/// return EOF, so a peer that aborts a handshake unblocks its counterpart.
pub(crate) fn tcp_pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = std::net::TcpStream::connect(addr).expect("connect loopback");
    let (server, _) = listener.accept().expect("accept loopback");
    (client, server)
}

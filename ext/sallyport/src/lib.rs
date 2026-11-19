//! sallyport: WireGuard and TCP in user space, behind a C ABI small
//! enough to bind by hand.
//!
//! No call here waits for a connection to be made. A connection is a
//! descriptor that is returned at once, and whether it was established
//! arrives on it, as its first byte. So the caller waits in its own I/O,
//! where it waits for everything else and can be interrupted.

mod config;
mod conn;
mod ctl;
mod engine;
mod keys;
mod packet;
mod pair;
mod peers;
mod sock;
mod sys;
mod tcp;

use engine::{Cmd, Engine, Knobs, Shared};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::net::IpAddr;
use std::os::fd::{IntoRawFd, OwnedFd, RawFd};
use std::panic::catch_unwind;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;

pub struct Handle {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    /// The UDP port, which the system chose if the configuration named
    /// none.
    port: u16,
}

// TLA-wake> \* Handle::pair. The lock makes the test of `dead` and the push one step.
// TLA-wake> \* A caller that is refused drops both ends of its pair.
// TLA-wake> CPush(c) == /\ s.cpc[c] = "push"
// TLA-wake>             /\ s' = IF s.dead THEN [s EXCEPT !.fd[c] = "closed", !.cpc[c] = "return"]
// TLA-wake>                               ELSE [s EXCEPT !.cmds = @ \cup {c}, !.fd[c] = "queued", !.cpc[c] = "wake"]
// TLA-wake> \* The wake comes after the lock is let go. The thread may have taken the
// TLA-wake> \* command by then, and may even have ended.
// TLA-wake> CWake(c) == /\ s.cpc[c] = "wake" /\ s' = Woke([s EXCEPT !.cpc[c] = "return"])
impl Handle {
    /// Makes a socket pair, queues the command that carries our end of
    /// it for the tunnel's thread, and returns Ruby's end. An error is an
    /// errno, which is ENETDOWN if the thread has ended and the system's
    /// error if the system refused the pair.
    fn pair(&self, kind: c_int, cmd: impl FnOnce(OwnedFd) -> Cmd) -> Result<RawFd, c_int> {
        let (ours, theirs) = sys::socketpair(kind).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut cmds = self.shared.cmds.lock().unwrap_or_else(|e| e.into_inner());
        if self.shared.dead.load(Ordering::Acquire) {
            return Err(libc::ENETDOWN);
        }
        cmds.push(cmd(ours));
        drop(cmds);
        self.shared.wake();
        Ok(theirs.into_raw_fd())
    }
}

/// Copies as much of the text as fits into the buffer, in whole
/// characters, and ends it with a NUL.
unsafe fn put(buf: *mut c_char, len: usize, s: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let mut n = s.len().min(len - 1);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    std::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), n);
    *buf.add(n) = 0;
}

unsafe fn text<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Starts a tunnel. A failure is an errno and a few words to go with it:
/// EINVAL and the fault for a fault in the configuration, or the system's
/// error and what it refused.
fn open(conf: &str, debug: &str) -> Result<Handle, (c_int, String)> {
    let fault = |e: String| (libc::EINVAL, e);
    let refused = |what: &str, e: std::io::Error| (e.raw_os_error().unwrap_or(libc::EIO), what.to_string());
    let cfg = config::parse(conf).map_err(fault)?;
    let knobs = Knobs::parse(debug).map_err(fault)?;
    let what = match cfg.listen_port {
        0 => "a UDP socket".to_string(),
        port => format!("UDP port {port}"),
    };
    let udp = sys::udp_socket(cfg.listen_port).map_err(|e| refused(&what, e))?;
    let port = udp.0.local_addr().map_err(|e| refused(&what, e))?.port();
    let wake = sys::pipe().map_err(|e| refused("a pipe", e))?;
    let (engine, shared) = Engine::new(&cfg, knobs, udp, wake).map_err(fault)?;
    let thread = std::thread::Builder::new().name("sallyport".into()).spawn(move || engine.run());
    Ok(Handle { shared, thread: Some(thread.map_err(|e| refused("a thread", e))?), port })
}

/// Returns the library's version, which the gem checks against its own.
#[no_mangle]
pub extern "C" fn sp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Starts a tunnel from a configuration in wg-quick's format, and returns
/// a handle to it. `debug` is NULL, or the knobs that engine.rs lists. If
/// the tunnel cannot be started, returns NULL, sets errno and writes the
/// reason into `err`. errno is EINVAL for a fault in the configuration or
/// in the knobs.
///
/// # Safety
/// `conf` is a C string, and `debug` is one or NULL. `err` has room for
/// `errlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn sp_open(
    conf: *const c_char,
    debug: *const c_char,
    err: *mut c_char,
    errlen: usize,
) -> *mut c_void {
    let conf = text(conf);
    let debug = if debug.is_null() { Some("") } else { text(debug) };
    let opened = catch_unwind(|| match (conf, debug) {
        (Some(conf), Some(debug)) => open(conf, debug),
        _ => Err((libc::EINVAL, "the configuration is not UTF-8".into())),
    });
    let (errno, reason) = match opened {
        Ok(Ok(handle)) => return Box::into_raw(Box::new(handle)).cast(),
        Ok(Err(failure)) => failure,
        Err(_) => (libc::EIO, "the library panicked".into()),
    };
    put(err, errlen, &reason);
    *libc::__errno_location() = errno;
    std::ptr::null_mut()
}

// TLA-wake> \* sp_close tells the thread to stop, wakes it and waits for it to end.
// TLA-wake> KStop == /\ s.kpc = "stop" /\ s' = [s EXCEPT !.stop = TRUE, !.kpc = "wake"]
// TLA-wake> KWake == /\ s.kpc = "wake" /\ s' = Woke([s EXCEPT !.kpc = "join"])
// TLA-wake> KJoin == /\ s.kpc = "join" /\ s.epc = "done" /\ s' = [s EXCEPT !.kpc = "free"]
// TLA-wake> \* The handle is then dropped, and both ends of the pipe are closed with
// TLA-wake> \* it. Only this thread knows that nothing is left to use either end.
// TLA-wake> KFree == /\ s.kpc = "free"
// TLA-wake>          /\ s' = [s EXCEPT !.rOpen = FALSE, !.wOpen = FALSE, !.freed = TRUE, !.kpc = "return"]
/// Stops a tunnel. Its listeners stop at once. Each connection is ended
/// as if its descriptor had been closed: what was written to it is sent,
/// and then the end of the stream, and a write to it fails from then on.
/// The call waits for that for up to `linger_ms` milliseconds, and a
/// connection that has not ended by then is reset. Every descriptor of
/// the tunnel then reaches end of file.
///
/// # Safety
/// `h` came from sp_open, and is not used again.
#[no_mangle]
pub unsafe extern "C" fn sp_close(h: *mut c_void, linger_ms: c_int) {
    if h.is_null() {
        return;
    }
    let mut h = Box::from_raw(h.cast::<Handle>());
    h.shared.linger.store(linger_ms.max(0) as u32, Ordering::Release);
    h.shared.stop.store(true, Ordering::Release);
    h.shared.wake();
    if let Some(thread) = h.thread.take() {
        let _ = thread.join();
    }
    // The pipe is closed here, as the handle is dropped. The thread has
    // ended, and nothing else can write to the pipe or wait on it.
}

/// Begins a TCP connection through the tunnel, and returns a descriptor
/// for it at once. The first byte read from the descriptor is a status.
/// It is 0 once the connection is established, and the connection's
/// stream follows it. Otherwise it is 1 for refused, 2 for timed out, 3
/// for an address that no peer takes, or 4 for no local port left, and
/// the stream ends. Closing the descriptor before the status arrives
/// abandons the attempt.
///
/// Returns -1 and sets errno if no connection was begun: EINVAL if `addr`
/// is not an IP address or `port` not a port, ENETDOWN if the tunnel's
/// thread has ended, or the system's error.
///
/// # Safety
/// `h` came from sp_open, and `addr` is a C string.
#[no_mangle]
pub unsafe extern "C" fn sp_connect(h: *mut c_void, addr: *const c_char, port: c_int) -> c_int {
    let h = &*h.cast::<Handle>();
    let addr = text(addr).and_then(|addr| addr.parse::<IpAddr>().ok());
    let port = u16::try_from(port).ok().filter(|port| *port != 0);
    let begun = match (addr, port) {
        (Some(addr), Some(port)) => h.pair(libc::SOCK_STREAM, |fd| Cmd::Connect { fd, addr, port }),
        _ => Err(libc::EINVAL),
    };
    begun.unwrap_or_else(|errno| {
        *libc::__errno_location() = errno;
        -1
    })
}

/// Listens on a TCP port of the tunnel's addresses, and returns a
/// descriptor for the listener at once. The descriptor is a socket that
/// keeps messages apart (SOCK_SEQPACKET). Its first message is a status
/// of one byte: 0 if the tunnel now listens on the port, or 5 if it
/// listened there already, and then the stream ends. After the status,
/// each connection arrives as a message "ADDRESS PORT", which names the
/// peer and carries the connection's descriptor (SCM_RIGHTS). The caller
/// answers each with a message of one byte, and at most `backlog`
/// connections wait for their answers. Closing the descriptor stops the
/// listening.
///
/// Returns -1 and sets errno if nothing was begun: EINVAL if `port` is
/// not a port, and otherwise as sp_connect does.
///
/// # Safety
/// `h` came from sp_open.
#[no_mangle]
pub unsafe extern "C" fn sp_listen(h: *mut c_void, port: c_int, backlog: c_int) -> c_int {
    let h = &*h.cast::<Handle>();
    let backlog = (backlog.max(1) as usize).min(ctl::MAX_BACKLOG);
    let begun = match u16::try_from(port).ok().filter(|port| *port != 0) {
        Some(port) => h.pair(libc::SOCK_SEQPACKET, |fd| Cmd::Listen { fd, port, backlog }),
        None => Err(libc::EINVAL),
    };
    begun.unwrap_or_else(|errno| {
        *libc::__errno_location() = errno;
        -1
    })
}

/// Returns how many connections the tunnel has: those that it is making,
/// and those that are made and have not ended. Returns -1 if the tunnel's
/// thread has ended.
///
/// # Safety
/// `h` came from sp_open.
#[no_mangle]
pub unsafe extern "C" fn sp_connections(h: *mut c_void) -> isize {
    let h = &*h.cast::<Handle>();
    if h.shared.dead.load(Ordering::Acquire) {
        return -1;
    }
    h.shared.connections.load(Ordering::Relaxed) as isize
}

/// Asks the tunnel's thread for a description of the tunnel, for a
/// person to read, and returns a descriptor for it at once. The thread
/// writes the description on the descriptor from the next turn of its
/// loop: what the tunnel has counted, then a line for each peer as
/// sp_stats gives it, then two lines for each connection. The stream then
/// ends. A stream that ends with nothing in it is that of a thread which
/// ended before it could answer.
///
/// Returns -1 and sets errno if nothing was begun, as sp_connect does.
///
/// # Safety
/// `h` came from sp_open.
#[no_mangle]
pub unsafe extern "C" fn sp_dump(h: *mut c_void) -> c_int {
    let h = &*h.cast::<Handle>();
    h.pair(libc::SOCK_STREAM, |fd| Cmd::Describe { fd }).unwrap_or_else(|errno| {
        *libc::__errno_location() = errno;
        -1
    })
}

/// Returns the tunnel's UDP port.
///
/// # Safety
/// `h` came from sp_open.
#[no_mangle]
pub unsafe extern "C" fn sp_port(h: *mut c_void) -> c_int {
    let h = &*h.cast::<Handle>();
    h.port.into()
}

/// Writes the state of the peers, as Peers::stats gives it and as it was
/// at most a quarter of a second ago, into `buf`. Returns how many bytes
/// the whole of it needs. If that is more than `len`, what was written
/// is cut short. Returns 0 if the tunnel's thread has ended, and with it
/// the sessions that the state was of.
///
/// # Safety
/// `h` came from sp_open, and `buf` has room for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn sp_stats(h: *mut c_void, buf: *mut c_char, len: usize) -> usize {
    let h = &*h.cast::<Handle>();
    if h.shared.dead.load(Ordering::Acquire) {
        return 0;
    }
    let stats = h.shared.stats.lock().unwrap_or_else(|e| e.into_inner());
    put(buf, len, &stats);
    stats.len() + 1
}

/// Writes a new private key, in base64, into 45 bytes. Returns 0, or -1
/// if the system gave no random bytes.
///
/// # Safety
/// `out` has room for 45 bytes.
#[no_mangle]
pub unsafe extern "C" fn sp_private_key(out: *mut c_char) -> c_int {
    let Ok(key) = catch_unwind(keys::generate) else { return -1 };
    put(out, 45, &keys::encode(&key));
    0
}

/// Writes the public key of a private key, both in base64, into 45 bytes.
/// Returns 0, or -1 if `private` is not a key.
///
/// # Safety
/// `private` is a C string, and `out` has room for 45 bytes.
#[no_mangle]
pub unsafe extern "C" fn sp_public_key(private: *const c_char, out: *mut c_char) -> c_int {
    let Some(private) = text(private).and_then(|t| keys::decode(t).ok()) else { return -1 };
    put(out, 45, &keys::encode(&keys::public(&private)));
    0
}

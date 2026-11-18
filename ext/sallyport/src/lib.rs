//! sallyport: WireGuard and TCP in user space, behind a C ABI small
//! enough to bind by hand.

mod config;
mod engine;
mod keys;
// Nothing sends a packet through a tunnel yet, so only the tests call
// some of this module.
#[allow(dead_code)]
mod peers;
mod sys;

use engine::{Engine, Shared};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::catch_unwind;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::JoinHandle;

pub struct Handle {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
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
fn open(conf: &str) -> Result<Handle, (c_int, String)> {
    let fault = |e: String| (libc::EINVAL, e);
    let refused = |what: &str, e: std::io::Error| (e.raw_os_error().unwrap_or(libc::EIO), what.to_string());
    let cfg = config::parse(conf).map_err(fault)?;
    let what = match cfg.listen_port {
        0 => "a UDP socket".to_string(),
        port => format!("UDP port {port}"),
    };
    let udp = sys::udp_socket(cfg.listen_port).map_err(|e| refused(&what, e))?;
    let wake = sys::pipe().map_err(|e| refused("a pipe", e))?;
    let (engine, shared) = Engine::new(&cfg, udp, wake).map_err(fault)?;
    let thread = std::thread::Builder::new().name("sallyport".into()).spawn(move || engine.run());
    Ok(Handle { shared, thread: Some(thread.map_err(|e| refused("a thread", e))?) })
}

/// Returns the library's version, which the gem checks against its own.
#[no_mangle]
pub extern "C" fn sp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Starts a tunnel from a configuration in wg-quick's format, and returns
/// a handle to it. If the tunnel cannot be started, returns NULL, sets
/// errno and writes the reason into `err`. errno is EINVAL for a fault in
/// the configuration.
///
/// # Safety
/// `conf` is a C string, and `err` has room for `errlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn sp_open(conf: *const c_char, err: *mut c_char, errlen: usize) -> *mut c_void {
    let conf = text(conf);
    let opened = catch_unwind(|| match conf {
        Some(conf) => open(conf),
        None => Err((libc::EINVAL, "the configuration is not UTF-8".into())),
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

/// Stops a tunnel.
///
/// # Safety
/// `h` came from sp_open, and is not used again.
#[no_mangle]
pub unsafe extern "C" fn sp_close(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    let mut h = Box::from_raw(h.cast::<Handle>());
    h.shared.stop.store(true, Ordering::Release);
    h.shared.wake();
    if let Some(thread) = h.thread.take() {
        let _ = thread.join();
    }
    // The pipe is closed here, as the handle is dropped. The thread has
    // ended, and nothing else can write to the pipe or wait on it.
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

//! sallyport: WireGuard and TCP in user space, behind a C ABI small
//! enough to bind by hand.

mod keys;
mod sys;

use std::ffi::{c_char, c_int, CStr};
use std::panic::catch_unwind;

/// Copies as much of the text as fits into the buffer, and ends it with
/// a NUL.
unsafe fn put(buf: *mut c_char, len: usize, s: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let n = s.len().min(len - 1);
    std::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), n);
    *buf.add(n) = 0;
}

unsafe fn text<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Returns the library's version, which the gem checks against its own.
#[no_mangle]
pub extern "C" fn sp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
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

//! sallyport: WireGuard and TCP in user space, behind a C ABI small
//! enough to bind by hand.

use std::ffi::c_char;

/// Returns the library's version, which the gem checks against its own.
#[no_mangle]
pub extern "C" fn sp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

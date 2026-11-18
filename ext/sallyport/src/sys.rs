//! The library reaches the operating system through this module.

use std::io::Read;

/// Fills the buffer from the system's random number generator.
pub fn random_fill(buf: &mut [u8]) {
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("/dev/urandom");
}

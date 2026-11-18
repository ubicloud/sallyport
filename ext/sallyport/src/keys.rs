//! A WireGuard key is 32 bytes, and is written in base64.

use crate::sys;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};

pub type Key = [u8; 32];

pub fn decode(text: &str) -> Result<Key, String> {
    let bytes = STANDARD.decode(text.trim()).ok();
    bytes.and_then(|b| Key::try_from(b).ok()).ok_or_else(|| "a key must be 32 bytes in base64".to_string())
}

pub fn encode(key: &Key) -> String {
    STANDARD.encode(key)
}

/// Makes a new private key, clamped as `wg genkey` clamps the keys it
/// makes.
pub fn generate() -> Key {
    let mut key = [0; 32];
    sys::random_fill(&mut key);
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    key
}

pub fn public(private: &Key) -> Key {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_32_bytes_in_base64() {
        let key = generate();
        assert_eq!(decode(&encode(&key)), Ok(key));
        assert_eq!(decode(&format!(" {}\n", encode(&key))), Ok(key));
        for bad in ["", "c2hvcnQ=", "not base64!", &encode(&key)[1..]] {
            assert_eq!(decode(bad), Err("a key must be 32 bytes in base64".to_string()));
        }
    }

    #[test]
    fn a_new_key_is_clamped_and_new() {
        let (a, b) = (generate(), generate());
        assert_ne!(a, b);
        for key in [a, b] {
            assert_eq!((key[0] & 7, key[31] & 128, key[31] & 64), (0, 0, 64));
        }
    }

    #[test]
    fn a_public_key_is_curve25519s() {
        // The private and public keys of Alice in RFC 7748, section 6.1.
        let private = decode("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=").unwrap();
        assert_eq!(encode(&public(&private)), "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
    }
}

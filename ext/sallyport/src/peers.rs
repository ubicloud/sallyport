//! This module is the WireGuard side of a tunnel. It holds the tunnel's
//! peers, and the rule that says which peer a packet goes to.

use crate::config::{contains, Config, Net};
use crate::keys::Key;
use std::net::{IpAddr, SocketAddr};

struct Peer {
    public: Key,
    allowed: Vec<Net>,
    endpoint: Option<SocketAddr>,
}

pub struct Peers {
    list: Vec<Peer>,
}

impl Peers {
    pub fn new(cfg: &Config) -> Result<Peers, String> {
        let mut list: Vec<Peer> = Vec::new();
        for p in &cfg.peers {
            if list.iter().any(|q| q.public == p.public) {
                return Err("two peers have the same PublicKey".into());
            }
            list.push(Peer { public: p.public, allowed: p.allowed.clone(), endpoint: p.endpoint });
        }
        Ok(Peers { list })
    }

    /// Finds the peer whose AllowedIPs hold the address. Where several
    /// do, the longest prefix wins, as in any routing table.
    fn route(&self, dst: &IpAddr) -> Option<usize> {
        let nets = self.list.iter().enumerate().flat_map(|(i, p)| p.allowed.iter().map(move |net| (net, i)));
        nets.filter(|(net, _)| contains(net, dst)).max_by_key(|(net, _)| net.1).map(|(_, i)| i)
    }

    /// Says whether some peer takes packets for the address.
    pub fn reaches(&self, dst: &IpAddr) -> bool {
        self.route(dst).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, keys};

    /// Returns a private key and its public key, in base64.
    fn key(n: u8) -> (String, String) {
        (keys::encode(&[n; 32]), keys::encode(&keys::public(&[n; 32])))
    }

    #[test]
    fn a_packet_goes_to_the_longest_prefix_or_nowhere() {
        let ((ours, _), (_, first), (_, second)) = (key(1), key(2), key(3));
        let conf = format!(
            "[Interface]\nPrivateKey = {ours}\nAddress = 10.9.0.1\n\
             [Peer]\nPublicKey = {first}\nAllowedIPs = 10.0.0.0/8, fd00::/8\n\
             [Peer]\nPublicKey = {second}\nAllowedIPs = 10.9.0.0/24"
        );
        let peers = Peers::new(&config::parse(&conf).unwrap()).unwrap();
        let route = |addr: &str| peers.route(&addr.parse().unwrap());
        assert_eq!(route("10.9.0.7"), Some(1));
        assert_eq!(route("10.9.1.7"), Some(0));
        assert_eq!(route("fd00::1"), Some(0));
        assert_eq!(route("192.0.2.1"), None);
        assert!(peers.reaches(&"10.1.1.1".parse().unwrap()));
        assert!(!peers.reaches(&"11.1.1.1".parse().unwrap()));
    }

    #[test]
    fn two_peers_may_not_share_a_key() {
        let ((ours, _), (_, peer)) = (key(1), key(2));
        let conf = format!(
            "[Interface]\nPrivateKey = {ours}\nAddress = 10.9.0.1\n\
             [Peer]\nPublicKey = {peer}\nAllowedIPs = 10.9.0.2/32\n\
             [Peer]\nPublicKey = {peer}\nAllowedIPs = 10.9.0.3/32"
        );
        assert_eq!(Peers::new(&config::parse(&conf).unwrap()).err().unwrap(), "two peers have the same PublicKey");
    }
}

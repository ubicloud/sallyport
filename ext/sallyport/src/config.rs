//! A tunnel's configuration, in the format of wg(8) and wg-quick(8).

use crate::keys::{self, Key};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// A network is an address and the length of its prefix.
pub type Net = (IpAddr, u8);

#[derive(Debug, PartialEq)]
pub struct PeerCfg {
    pub public: Key,
    pub psk: Option<Key>,
    pub endpoint: Option<SocketAddr>,
    pub allowed: Vec<Net>,
    pub keepalive: Option<u16>,
}

#[derive(Debug, PartialEq)]
pub struct Config {
    pub private: Key,
    pub addrs: Vec<IpAddr>,
    pub listen_port: u16,
    pub mtu: usize,
    pub peers: Vec<PeerCfg>,
}

/// These settings of wg and wg-quick mean nothing to a tunnel with no
/// interface, no routing table and no resolver. They are passed over, so
/// that a file written for wg-quick can be used as it is.
const PASSED_OVER: [&str; 8] = ["dns", "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark"];

/// The most addresses that a tunnel may have, which is the most that
/// smoltcp can be built to hold.
const MAX_ADDRS: usize = 8;

fn net(text: &str) -> Result<Net, String> {
    let (addr, len) = match text.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (text, None),
    };
    let addr: IpAddr = addr.trim().parse().map_err(|_| format!("bad address {text:?}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(len) => len.trim().parse::<u8>().ok().filter(|len| *len <= max),
        None => Some(max),
    };
    Ok((addr, len.ok_or_else(|| format!("bad prefix length in {text:?}"))?))
}

/// Says whether the network holds the address.
pub fn contains(net: &Net, addr: &IpAddr) -> bool {
    fn same(a: u128, b: u128, len: u8, width: u8) -> bool {
        len == 0 || (a ^ b) >> (width - len) == 0
    }
    match (net.0, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => same(u32::from(n).into(), u32::from(*a).into(), net.1, 32),
        (IpAddr::V6(n), IpAddr::V6(a)) => same(n.into(), (*a).into(), net.1, 128),
        _ => false,
    }
}

pub fn parse(text: &str) -> Result<Config, String> {
    let (mut private, mut addrs, mut listen_port, mut mtu) = (None, Vec::new(), 0, 1420);
    let mut peers: Vec<(Option<Key>, PeerCfg)> = Vec::new();
    let mut section = String::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = |e: String| format!("line {}: {e}", n + 1);
        if line.starts_with('[') {
            section = line.to_ascii_lowercase();
            match section.as_str() {
                "[interface]" => {}
                "[peer]" => {
                    let peer =
                        PeerCfg { public: [0; 32], psk: None, endpoint: None, allowed: Vec::new(), keepalive: None };
                    peers.push((None, peer));
                }
                _ => return Err(at(format!("unknown section {line}"))),
            }
            continue;
        }
        let (name, value) = line.split_once('=').ok_or_else(|| at("expected KEY = VALUE".into()))?;
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        let number = |v: &str| v.parse::<u16>().map_err(|_| at(format!("bad number {v:?}")));
        let list = |v: &str| v.split(',').map(net).collect::<Result<Vec<Net>, String>>().map_err(at);
        match (section.as_str(), name.as_str(), peers.last_mut()) {
            ("[interface]", "privatekey", _) => private = Some(keys::decode(value).map_err(at)?),
            ("[interface]", "address", _) => {
                for (addr, _) in list(value)? {
                    // No host has an address of another kind, and smoltcp
                    // would panic on a multicast or a broadcast one.
                    let unicast = match addr {
                        IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
                        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
                    };
                    if !unicast {
                        return Err(at(format!("a tunnel cannot have the address {addr}")));
                    }
                    addrs.push(addr);
                }
            }
            ("[interface]", "listenport", _) => listen_port = number(value)?,
            ("[interface]", "mtu", _) => mtu = number(value)? as usize,
            ("[interface]", name, _) if PASSED_OVER.contains(&name) => {}
            ("[peer]", "publickey", Some((public, _))) => *public = Some(keys::decode(value).map_err(at)?),
            ("[peer]", "presharedkey", Some((_, peer))) => peer.psk = Some(keys::decode(value).map_err(at)?),
            ("[peer]", "allowedips", Some((_, peer))) => peer.allowed.extend(list(value)?),
            ("[peer]", "persistentkeepalive", Some((_, peer))) => {
                peer.keepalive = if value == "off" { None } else { Some(number(value)?).filter(|k| *k > 0) }
            }
            ("[peer]", "endpoint", Some((_, peer))) => {
                // A host name is resolved here, once.
                let found = value.to_socket_addrs().ok().and_then(|mut addrs| addrs.next());
                peer.endpoint = Some(found.ok_or_else(|| at(format!("cannot resolve endpoint {value:?}")))?);
            }
            _ => return Err(at(format!("unknown key {name}"))),
        }
    }
    if addrs.is_empty() || addrs.len() > MAX_ADDRS {
        return Err(format!("a tunnel has from 1 to {MAX_ADDRS} addresses"));
    }
    // IPv6 requires of every link an MTU of 1280 at least.
    let least = if addrs.iter().any(IpAddr::is_ipv6) { 1280 } else { 576 };
    if !(least..=9000).contains(&mtu) {
        return Err(format!("the MTU must be from {least} to 9000"));
    }
    let peers = peers.into_iter().map(|(public, peer)| Some(PeerCfg { public: public?, ..peer }));
    Ok(Config {
        private: private.ok_or("no PrivateKey")?,
        addrs,
        listen_port,
        mtu,
        peers: peers.collect::<Option<_>>().ok_or("a peer has no PublicKey")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const PEER: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

    fn interface(rest: &str) -> String {
        format!("[Interface]\nPrivateKey = {KEY}\n{rest}")
    }

    #[test]
    fn a_file_for_wg_quick_is_read() {
        let config = parse(&format!(
            "[Interface]  # ours\n\
             PrivateKey = {KEY}\n\
             Address = 10.9.0.1/24, fd09::1/64\n\
             Address = 10.9.1.1\n\
             ListenPort = 51820\n\
             MTU = 1380\n\
             DNS = 10.9.0.53\n\
             FwMark = 51820\n\
             PostUp = iptables -A FORWARD -i %i -j ACCEPT\n\
             \n\
             [peer]\n\
             publickey={PEER}\n\
             PresharedKey = {KEY}\n\
             Endpoint = [::1]:51821\n\
             AllowedIPs = 10.9.0.0/24, fd09::/64\n\
             AllowedIPs = 0.0.0.0/0\n\
             PersistentKeepalive = 25\n\
             [Peer]\n\
             PublicKey = {KEY}\n\
             PersistentKeepalive = off\n"
        ))
        .unwrap();
        let (key, peer) = (keys::decode(KEY).unwrap(), keys::decode(PEER).unwrap());
        let addr = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(config.private, key);
        assert_eq!(config.addrs, [addr("10.9.0.1"), addr("fd09::1"), addr("10.9.1.1")]);
        assert_eq!((config.listen_port, config.mtu), (51820, 1380));
        let first = PeerCfg {
            public: peer,
            psk: Some(key),
            endpoint: Some("[::1]:51821".parse().unwrap()),
            allowed: vec![(addr("10.9.0.0"), 24), (addr("fd09::"), 64), (addr("0.0.0.0"), 0)],
            keepalive: Some(25),
        };
        let second = PeerCfg { public: key, psk: None, endpoint: None, allowed: vec![], keepalive: None };
        assert_eq!(config.peers, [first, second]);
    }

    #[test]
    fn what_is_left_out_has_a_default() {
        let config = parse(&interface("Address = 10.9.0.1")).unwrap();
        assert_eq!((config.listen_port, config.mtu, config.peers.len()), (0, 1420, 0));
    }

    #[test]
    fn a_fault_is_named_with_its_line() {
        let cases = [
            (interface("Address = 10.9.0.1\nColour = red"), "line 4: unknown key colour"),
            (interface("Address = 10.9.0.1\n[Pier]"), "line 4: unknown section [Pier]"),
            (interface("Address = 10.9.0.1\nListenPort"), "line 4: expected KEY = VALUE"),
            (interface("Address = 10.9.0.1\nListenPort = 70000"), "line 4: bad number \"70000\""),
            (interface("Address = 10.9.0.300"), "line 3: bad address \"10.9.0.300\""),
            (interface("Address = 10.9.0.1/33"), "line 3: bad prefix length in \"10.9.0.1/33\""),
            (interface("Address = 224.0.0.1"), "line 3: a tunnel cannot have the address 224.0.0.1"),
            (interface("Address = 10.9.0.1, ff02::1"), "line 3: a tunnel cannot have the address ff02::1"),
            (interface("Address = 255.255.255.255"), "line 3: a tunnel cannot have the address 255.255.255.255"),
            (interface("Address = ::"), "line 3: a tunnel cannot have the address ::"),
            (interface("Address = 10.9.0.1\nPublicKey = x"), "line 4: unknown key publickey"),
            ("[Interface]\nPrivateKey = short".to_string(), "line 2: a key must be 32 bytes in base64"),
            (
                interface("Address = 10.9.0.1\n[Peer]\nEndpoint = nowhere"),
                "line 5: cannot resolve endpoint \"nowhere\"",
            ),
            ("Address = 10.9.0.1".to_string(), "line 1: unknown key address"),
        ];
        for (text, fault) in cases {
            assert_eq!(parse(&text).unwrap_err(), fault);
        }
    }

    #[test]
    fn a_tunnel_needs_a_key_an_address_and_a_sane_mtu() {
        let many = (1..=9).map(|n| format!("10.9.0.{n}")).collect::<Vec<_>>().join(", ");
        let cases = [
            ("[Interface]\nAddress = 10.9.0.1".to_string(), "no PrivateKey"),
            (interface(""), "a tunnel has from 1 to 8 addresses"),
            (interface(&format!("Address = {many}")), "a tunnel has from 1 to 8 addresses"),
            (interface("Address = 10.9.0.1\nMTU = 575"), "the MTU must be from 576 to 9000"),
            (interface("Address = fd09::1\nMTU = 1279"), "the MTU must be from 1280 to 9000"),
            (interface("Address = 10.9.0.1\nMTU = 9001"), "the MTU must be from 576 to 9000"),
            (interface("Address = 10.9.0.1\n[Peer]\nAllowedIPs = 10.9.0.2/32"), "a peer has no PublicKey"),
        ];
        for (text, fault) in cases {
            assert_eq!(parse(&text).unwrap_err(), fault);
        }
        assert!(parse(&interface("Address = 10.9.0.1\nMTU = 576")).is_ok());
        assert!(parse(&interface("Address = fd09::1\nMTU = 1280")).is_ok());
    }

    #[test]
    fn a_network_holds_the_addresses_under_its_prefix() {
        let holds = |net_text: &str, addr: &str| contains(&net(net_text).unwrap(), &addr.parse().unwrap());
        assert!(holds("10.9.0.0/24", "10.9.0.255") && !holds("10.9.0.0/24", "10.9.1.0"));
        assert!(holds("10.9.0.7/24", "10.9.0.1"), "the bits past the prefix do not count");
        assert!(holds("10.9.0.1/32", "10.9.0.1") && !holds("10.9.0.1/32", "10.9.0.0"));
        assert!(holds("10.9.0.1", "10.9.0.1") && !holds("10.9.0.1", "10.9.0.2"));
        assert!(holds("0.0.0.0/0", "203.0.113.9") && !holds("0.0.0.0/0", "fd09::1"));
        assert!(holds("fd09::/16", "fd09:1::1") && !holds("fd09::/16", "fd0a::1"));
        assert!(holds("fd09::1/128", "fd09::1") && !holds("fd09::1/128", "fd09::2"));
        assert!(holds("::/0", "2001:db8::1") && !holds("::/0", "10.9.0.1"));
    }
}

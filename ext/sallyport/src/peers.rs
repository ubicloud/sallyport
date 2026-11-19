//! This module is the WireGuard side of a tunnel. It keeps a session with
//! each peer, by boringtun, and holds the rule that says which peer a
//! packet goes to.

use crate::config::{contains, Config, Net};
use crate::keys::{self, Key};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// A Sender is how a datagram leaves. A tunnel gives one that writes to its
/// UDP socket, and a test gives one that keeps the datagram.
pub type Sender<'a> = &'a mut dyn FnMut(&[u8], SocketAddr);

/// The first byte of a cookie reply, which is the one message that
/// boringtun sends to a peer that has proved nothing.
const COOKIE_REPLY: u8 = 3;
/// A cookie reply is this long.
const COOKIE_REPLY_LEN: usize = 64;
/// A tunnel takes this many handshake messages from its peers in a
/// second before it asks each sender for a cookie. The device that
/// boringtun has takes as many.
const HANDSHAKES_PER_SECOND: u64 = 100;

/// The kinds of message that WireGuard has.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Initiation,
    Response,
    CookieReply,
    Data,
}

struct Peer {
    tunn: Tunn,
    public: Key,
    allowed: Vec<Net>,
    endpoint: Option<SocketAddr>,
    keepalive: bool,
}

/// Dropped counts the datagrams that named no peer, those that boringtun
/// refused, and the packets from a source that their peer may not use.
#[derive(Debug, Default, PartialEq)]
pub struct Dropped {
    pub unknown: u64,
    pub refused: u64,
    pub disallowed: u64,
}

pub struct Peers {
    secret: StaticSecret,
    public: PublicKey,
    /// The tunnel has these addresses.
    own: Vec<IpAddr>,
    list: Vec<Peer>,
    /// The limiter checks the MACs of a handshake message, and counts the
    /// messages. Every session has it too, so that all of them check a
    /// cookie against the one secret.
    limiter: Arc<RateLimiter>,
    buf: Vec<u8>,
    pub dropped: Dropped,
}

impl Peers {
    pub fn new(cfg: &Config) -> Result<Peers, String> {
        let secret = StaticSecret::from(cfg.private);
        let public = PublicKey::from(&secret);
        // A handshake message from a peer is counted twice, once in
        // receive and once by its session, so the limit is twice what is
        // meant. A message that names no peer reaches no session and is
        // counted once, so twice as many of those are taken.
        let limiter = Arc::new(RateLimiter::new(&public, 2 * HANDSHAKES_PER_SECOND));
        let mut list: Vec<Peer> = Vec::new();
        for (i, p) in cfg.peers.iter().enumerate() {
            if list.iter().any(|q| q.public == p.public) {
                return Err("two peers have the same PublicKey".into());
            }
            // boringtun puts the index in the high 24 bits of each session
            // index that it gives this peer, and peer_of reads it back.
            let (theirs, limiter) = (PublicKey::from(p.public), Some(limiter.clone()));
            let tunn = Tunn::new(secret.clone(), theirs, p.psk, p.keepalive, i as u32, limiter);
            let (allowed, keepalive) = (p.allowed.clone(), p.keepalive.is_some());
            list.push(Peer { tunn, public: p.public, allowed, endpoint: p.endpoint, keepalive });
        }
        let own = cfg.addrs.clone();
        Ok(Peers { secret, public, own, list, limiter, buf: vec![0; 65536], dropped: Dropped::default() })
    }

    /// Begins a handshake with each peer that has a keepalive and a known
    /// endpoint, as the kernel's WireGuard does when an interface comes
    /// up. boringtun would begin when the first keepalive fell due.
    pub fn start(&mut self, send: Sender) {
        for peer in self.list.iter_mut().filter(|peer| peer.keepalive) {
            let Some(to) = peer.endpoint else { continue };
            if let TunnResult::WriteToNetwork(b) = peer.tunn.format_handshake_initiation(&mut self.buf, false) {
                send(b, to);
            }
        }
    }

    /// Finds the peer that a message is from, and the kind of message
    /// that it is. A handshake initiation names its sender by static key,
    /// which takes a key exchange to read. Every other message carries a
    /// session index of ours.
    fn peer_of(&self, message: &Packet) -> Option<(usize, Kind)> {
        let (index, kind) = match message {
            Packet::HandshakeInit(p) => {
                let half = parse_handshake_anon(&self.secret, &self.public, p).ok()?;
                let i = self.list.iter().position(|q| q.public == half.peer_static_public)?;
                return Some((i, Kind::Initiation));
            }
            Packet::HandshakeResponse(p) => (p.receiver_idx, Kind::Response),
            Packet::PacketCookieReply(p) => (p.receiver_idx, Kind::CookieReply),
            Packet::PacketData(p) => (p.receiver_idx, Kind::Data),
        };
        Some(((index >> 8) as usize, kind)).filter(|(i, _)| *i < self.list.len())
    }

    /// Takes a datagram that arrived from `from`, and returns the IP
    /// packet that it carried, if it carried one that its peer may send.
    pub fn receive(&mut self, datagram: &[u8], from: SocketAddr, send: Sender) -> Option<Vec<u8>> {
        // A handshake message is checked before a key exchange is spent
        // on it. Its first MAC shows that the sender knows our public
        // key. When more handshake messages arrive than a second should
        // bring, the second MAC must show that the sender had a cookie
        // of us at the address that it gives, and it is sent one if not.
        let mut cookie = [0; COOKIE_REPLY_LEN];
        let message = match self.limiter.verify_packet(Some(from.ip()), datagram, &mut cookie) {
            Ok(message) => Some(message),
            Err(TunnResult::WriteToNetwork(reply)) => {
                send(reply, from);
                None
            }
            Err(_) => None,
        };
        let Some((i, kind)) = message.and_then(|message| self.peer_of(&message)) else {
            self.dropped.unknown += 1;
            return None;
        };
        let peer = &mut self.list[i];
        let mut packet = None;
        // A peer is where its last authenticated message came from. A cookie
        // reply is the one message that is not authenticated, whichever of us
        // sends it.
        match peer.tunn.decapsulate(Some(from.ip()), datagram, &mut self.buf) {
            TunnResult::Err(_) => {
                self.dropped.refused += 1;
                return None;
            }
            TunnResult::Done => {
                if kind == Kind::Data {
                    peer.endpoint = Some(from);
                }
            }
            TunnResult::WriteToNetwork(b) => {
                send(b, from);
                if b[0] == COOKIE_REPLY {
                    return None;
                }
                peer.endpoint = Some(from);
            }
            TunnResult::WriteToTunnelV4(p, src) => {
                peer.endpoint = Some(from);
                packet = Some((p.to_vec(), IpAddr::V4(src)));
            }
            TunnResult::WriteToTunnelV6(p, src) => {
                peer.endpoint = Some(from);
                packet = Some((p.to_vec(), IpAddr::V6(src)));
            }
        }
        // boringtun holds the packets that it was given while no session
        // was up, and sends them only when asked, with an empty datagram,
        // one for each call. A session is up once the peer has answered
        // our initiation, or has sent data after its own. To ask after its
        // initiation would be too soon, and boringtun would begin a second
        // handshake for the packet that it cannot yet send.
        if let (Kind::Response | Kind::Data, Some(to)) = (kind, peer.endpoint) {
            while let TunnResult::WriteToNetwork(b) = peer.tunn.decapsulate(None, &[], &mut self.buf) {
                send(b, to);
            }
        }
        // A peer speaks only for the addresses that are routed to it: a
        // packet to such an address goes to that peer and to no other. The
        // peer's key vouches for a packet that gets this far, and the
        // packet is taken if its source is such an address. Where the
        // AllowedIPs of two peers overlap, neither can send as an address
        // that the other holds more closely.
        let (packet, src) = packet?;
        if self.route(&src) == Some(i) && !self.stray(&src) {
            Some(packet)
        } else {
            self.dropped.disallowed += 1;
            None
        }
    }

    /// Finds the peer whose AllowedIPs hold the address. Where several
    /// do, the longest prefix wins, as in any routing table. If two peers
    /// have the same net, it is the later one's, as it is to the kernel's
    /// WireGuard when it is given the two in that order.
    fn route(&self, dst: &IpAddr) -> Option<usize> {
        let nets = self.list.iter().enumerate().flat_map(|(i, p)| p.allowed.iter().map(move |net| (net, i)));
        nets.filter(|(net, _)| contains(net, dst)).max_by_key(|(net, _)| net.1).map(|(_, i)| i)
    }

    /// Says whether no peer can have the address, whatever its
    /// AllowedIPs say: the tunnel has it, or it is one that no host has
    /// on a link. Linux drops a packet from most of these sources too. A
    /// peer that is a gateway has every address in its AllowedIPs. Some
    /// programs trust what comes from the loopback address, and they
    /// must not hear that peer there.
    fn stray(&self, src: &IpAddr) -> bool {
        self.own.contains(src)
            || match src {
                IpAddr::V4(src) => {
                    src.is_loopback() || src.is_multicast() || src.is_broadcast() || src.is_unspecified()
                }
                IpAddr::V6(src) => {
                    src.is_loopback() || src.is_multicast() || src.is_unspecified() || src.to_ipv4_mapped().is_some()
                }
            }
    }

    /// Says whether some peer takes packets for the address.
    pub fn reaches(&self, dst: &IpAddr) -> bool {
        self.route(dst).is_some()
    }

    /// Sends an IP packet to the peer that takes its destination. A packet
    /// for no peer is dropped, and so is one for a peer that we cannot
    /// reach until it speaks first.
    pub fn send(&mut self, packet: &[u8], send: Sender) {
        let Some(i) = Tunn::dst_address(packet).and_then(|dst| self.route(&dst)) else { return };
        let peer = &mut self.list[i];
        let Some(to) = peer.endpoint else { return };
        if let TunnResult::WriteToNetwork(b) = peer.tunn.encapsulate(packet, &mut self.buf) {
            send(b, to);
        }
    }

    /// Runs boringtun's timers, which rekey, keep alive and retry
    /// handshakes.
    pub fn tick(&mut self, send: Sender) {
        // The limiter begins a new count once a second has passed.
        self.limiter.reset_count();
        for peer in &mut self.list {
            let mut due = peer.tunn.update_timers(&mut self.buf);
            // boringtun gives a handshake up when it has had no answer for
            // 90 seconds, and begins another only when it has a packet to
            // send. A peer with a keepalive is tried again at once, as
            // WireGuard proper tries it at each keepalive, so that a peer
            // that was away is found when it comes back.
            if matches!(due, TunnResult::Err(WireGuardError::ConnectionExpired)) && peer.keepalive {
                due = peer.tunn.format_handshake_initiation(&mut self.buf, false);
            }
            if let (TunnResult::WriteToNetwork(b), Some(to)) = (due, peer.endpoint) {
                send(b, to);
            }
        }
    }

    /// Writes a line for each peer: its public key, its endpoint or "-",
    /// the milliseconds since its last handshake or -1, and the bytes of
    /// the packets sent to it and received from it.
    pub fn stats(&self, out: &mut String) {
        for peer in &self.list {
            let (age, sent, received, _, _) = peer.tunn.stats();
            let endpoint = peer.endpoint.map_or("-".into(), |e| e.to_string());
            let age = age.map_or(-1, |age| age.as_millis() as i64);
            let _ = writeln!(out, "{} {endpoint} {age} {sent} {received}", keys::encode(&peer.public));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, keys};
    use std::collections::VecDeque;

    const A: &str = "10.9.0.1";
    const B: &str = "10.9.0.2";

    /// Returns a private key and its public key, in base64.
    fn key(n: u8) -> (String, String) {
        (keys::encode(&[n; 32]), keys::encode(&keys::public(&[n; 32])))
    }

    fn at(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    /// Builds the peers of two tunnels, A and B, each of which has the
    /// other for its only peer. Only B is told where the other is.
    fn pair() -> (Peers, Peers) {
        pair_with("")
    }

    /// Builds the pair with another line in what each is told of its peer.
    fn pair_with(line: &str) -> (Peers, Peers) {
        let ((ka, pa), (kb, pb)) = (key(1), key(2));
        let a = format!(
            "[Interface]\nPrivateKey = {ka}\nAddress = {A}\n\
             [Peer]\nPublicKey = {pb}\nAllowedIPs = {B}/32\n{line}"
        );
        let b = format!(
            "[Interface]\nPrivateKey = {kb}\nAddress = {B}\n\
             [Peer]\nPublicKey = {pa}\nAllowedIPs = {A}/32\nEndpoint = 192.0.2.1:1\n{line}"
        );
        (Peers::new(&config::parse(&a).unwrap()).unwrap(), Peers::new(&config::parse(&b).unwrap()).unwrap())
    }

    /// What settle returns: the IP packets that came out of A and of B,
    /// and the type of each WireGuard message that crossed, in order.
    type Settled = (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<u8>);

    /// Carries datagrams between the two until neither has more to send.
    /// A is at port 1, and B at `b_port`.
    fn settle(a: &mut Peers, b: &mut Peers, to_a: &mut VecDeque<Vec<u8>>, b_port: u16) -> Settled {
        let (mut to_b, mut out_a, mut out_b, mut types) = (VecDeque::new(), Vec::new(), Vec::new(), Vec::new());
        while !to_a.is_empty() || !to_b.is_empty() {
            if let Some(d) = to_a.pop_front() {
                types.push(d[0]);
                out_a.extend(a.receive(&d, at(b_port), &mut |d, _| to_b.push_back(d.to_vec())));
            }
            if let Some(d) = to_b.pop_front() {
                types.push(d[0]);
                out_b.extend(b.receive(&d, at(1), &mut |d, _| to_a.push_back(d.to_vec())));
            }
        }
        (out_a, out_b, types)
    }

    /// Builds a small IPv4 packet from one address to another.
    fn ip(src: &str, dst: &str) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 24, 0, 0, 0, 0, 64, 253, 0, 0];
        for addr in [src, dst] {
            p.extend(addr.parse::<std::net::Ipv4Addr>().unwrap().octets());
        }
        p.extend(b"data");
        p
    }

    /// Returns the datagrams that sending an IP packet produces.
    fn sent(peers: &mut Peers, packet: &[u8]) -> VecDeque<Vec<u8>> {
        let mut out = VecDeque::new();
        peers.send(packet, &mut |d, _| out.push_back(d.to_vec()));
        out
    }

    #[test]
    fn a_packet_crosses_each_way() {
        let (mut a, mut b) = pair();
        // The first packet has to wait for a handshake, which it starts.
        let there = ip(B, A);
        let mut datagrams = sent(&mut b, &there);
        let (out_a, out_b, types) = settle(&mut a, &mut b, &mut datagrams, 2);
        assert_eq!((out_a, out_b), (vec![there], vec![]));
        // These are an initiation, its response, a keepalive that confirms
        // the session, and the packet.
        assert_eq!(types, [1, 2, 4, 4]);
        let back = ip(A, B);
        let mut datagrams = sent(&mut a, &back);
        assert_eq!(datagrams.len(), 1);
        assert_eq!(b.receive(&datagrams.pop_front().unwrap(), at(1), &mut |_, _| ()), Some(back));
    }

    #[test]
    fn a_peer_is_where_it_last_spoke_from() {
        let (mut a, mut b) = pair();
        assert_eq!(a.list[0].endpoint, None);
        assert!(sent(&mut a, &ip(A, B)).is_empty(), "A cannot reach B until B speaks");
        let mut datagrams = sent(&mut b, &ip(B, A));
        settle(&mut a, &mut b, &mut datagrams, 2);
        assert_eq!(a.list[0].endpoint, Some(at(2)));
        let mut datagrams = sent(&mut b, &ip(B, A));
        settle(&mut a, &mut b, &mut datagrams, 7);
        assert_eq!(a.list[0].endpoint, Some(at(7)));
    }

    #[test]
    fn a_peer_with_a_keepalive_is_greeted_at_once() {
        let (mut a, mut b) = pair_with("PersistentKeepalive = 25");
        a.start(&mut |_, _| panic!("A does not know where B is"));
        let mut datagrams = VecDeque::new();
        b.start(&mut |d, to| {
            assert_eq!(to, at(1));
            datagrams.push_back(d.to_vec());
        });
        let (_, _, types) = settle(&mut a, &mut b, &mut datagrams, 2);
        assert_eq!(types, [1, 2, 4], "an initiation, its response, and a keepalive that confirms the session");
        // A now knows where B is, and has a session to send in.
        let back = ip(A, B);
        let mut datagrams = sent(&mut a, &back);
        assert_eq!(datagrams.len(), 1);
        assert_eq!(b.receive(&datagrams.pop_front().unwrap(), at(1), &mut |_, _| ()), Some(back));

        let (_, mut b) = pair();
        b.start(&mut |_, _| panic!("B has no keepalive"));
    }

    /// This test waits out the 90 seconds for which boringtun tries a
    /// handshake, so it runs only when asked for, as "rake slow" asks.
    #[test]
    #[ignore]
    fn a_peer_with_a_keepalive_is_tried_for_as_long_as_it_is_silent() {
        let (_, mut b) = pair_with("PersistentKeepalive = 25");
        let begun = std::time::Instant::now();
        let mut sent = Vec::new();
        b.start(&mut |_, _| sent.push(begun.elapsed().as_secs()));
        while begun.elapsed().as_secs() < 110 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            b.tick(&mut |d, _| {
                assert_eq!(d[0], 1, "nothing but an initiation is sent");
                sent.push(begun.elapsed().as_secs());
            });
        }
        assert!(sent.iter().filter(|at| **at > 95).count() >= 2, "initiations left at {sent:?}");
    }

    #[test]
    fn a_handshake_with_a_bad_mac_is_dropped() {
        let (mut a, mut b) = pair();
        let mut datagrams = sent(&mut b, &ip(B, A));
        let good = datagrams.pop_front().unwrap();
        // The first MAC is the 16 bytes before the last 16.
        let mut bad = good.clone();
        bad[good.len() - 32] ^= 1;
        assert_eq!(a.receive(&bad, at(2), &mut |_, _| panic!("a bad MAC gets no answer")), None);
        assert_eq!(a.dropped, Dropped { unknown: 1, refused: 0, disallowed: 0 });
        let mut answers = 0;
        a.receive(&good, at(2), &mut |_, _| answers += 1);
        assert_eq!(answers, 1);
    }

    #[test]
    fn a_flood_of_handshakes_is_asked_for_cookies() {
        let (mut a, _) = pair();
        // A session of B makes the initiations, each newer than the last.
        let theirs = PublicKey::from(keys::public(&[1; 32]));
        let mut b = Tunn::new(StaticSecret::from([2; 32]), theirs, None, None, 0, None);
        let mut buf = [0; 256];
        let mut answer = |a: &mut Peers, b: &mut Tunn| {
            let TunnResult::WriteToNetwork(initiation) = b.format_handshake_initiation(&mut buf, true) else {
                panic!("no initiation");
            };
            let mut answer = Vec::new();
            a.receive(initiation, at(2), &mut |d, _| answer = d.to_vec());
            answer
        };
        for _ in 0..HANDSHAKES_PER_SECOND {
            assert_eq!(answer(&mut a, &mut b)[0], 2, "a response");
        }
        let reply = answer(&mut a, &mut b);
        assert_eq!(reply[0], COOKIE_REPLY);
        // B takes the cookie, and its next initiation carries the MAC
        // that the cookie makes.
        assert!(matches!(b.decapsulate(None, &reply, &mut [0; 256]), TunnResult::Done));
        assert_eq!(answer(&mut a, &mut b)[0], 2);
        // A second later A counts afresh.
        std::thread::sleep(std::time::Duration::from_millis(1001));
        a.tick(&mut |_, _| ());
        let mut fresh = Tunn::new(StaticSecret::from([2; 32]), theirs, None, None, 0, None);
        assert_eq!(answer(&mut a, &mut fresh)[0], 2);
    }

    #[test]
    fn a_peer_is_described_in_a_line() {
        let (mut a, mut b) = pair();
        let described = |peers: &Peers| {
            let mut text = String::new();
            peers.stats(&mut text);
            text
        };
        assert_eq!(described(&a), format!("{} - -1 0 0\n", key(2).1));
        assert_eq!(described(&b), format!("{} 192.0.2.1:1 -1 0 0\n", key(1).1));
        let mut datagrams = sent(&mut b, &ip(B, A));
        settle(&mut a, &mut b, &mut datagrams, 2);
        let text = described(&a);
        let fields: Vec<&str> = text.split(' ').collect();
        assert_eq!(fields[..2], [key(2).1.as_str(), "192.0.2.1:2"]);
        assert!(fields[2].parse::<u32>().unwrap() < 60_000, "the handshake was a moment ago");
        assert_eq!(fields[3..], ["0", "24\n"], "A received the 24 bytes of the packet");
    }

    #[test]
    fn a_packet_held_for_a_session_goes_when_the_peer_begins_one() {
        let (mut a, mut b) = pair();
        a.list[0].endpoint = Some(at(2));
        let held = ip(A, B);
        assert_eq!(sent(&mut a, &held).len(), 1, "A begins a handshake, which is lost");
        let there = ip(B, A);
        let mut datagrams = sent(&mut b, &there);
        let (out_a, out_b, types) = settle(&mut a, &mut b, &mut datagrams, 2);
        assert_eq!((out_a, out_b), (vec![there], vec![held]));
        assert_eq!(types.iter().filter(|t| **t == 1).count(), 1, "B's handshake served both");
    }

    #[test]
    fn a_source_outside_allowed_ips_is_dropped() {
        let (mut a, mut b) = pair();
        let mut datagrams = sent(&mut b, &ip("10.9.0.3", A));
        let (out_a, _, types) = settle(&mut a, &mut b, &mut datagrams, 2);
        assert!(out_a.is_empty());
        assert_eq!(types, [1, 2, 4, 4], "the session is good, and only the packet is refused");
        assert_eq!(a.dropped, Dropped { unknown: 0, refused: 0, disallowed: 1 });
        // The same peer is heard when it sends from its own address.
        let mut datagrams = sent(&mut b, &ip(B, A));
        assert_eq!(settle(&mut a, &mut b, &mut datagrams, 2).0, [ip(B, A)]);
    }

    /// Builds the peers of a tunnel at 10.9.0.1 that has two peers, and
    /// the peers of each of those two. The first peer is at port 2 and
    /// the second at port 3.
    fn three(first: &str, second: &str) -> (Peers, Peers, Peers) {
        let ((ka, pa), (kb, pb), (kc, pc)) = (key(1), key(2), key(3));
        let a = format!(
            "[Interface]\nPrivateKey = {ka}\nAddress = {A}\n\
             [Peer]\nPublicKey = {pb}\nAllowedIPs = {first}\n\
             [Peer]\nPublicKey = {pc}\nAllowedIPs = {second}"
        );
        let other = |key: &str| {
            let conf = format!(
                "[Interface]\nPrivateKey = {key}\nAddress = {B}\n\
                 [Peer]\nPublicKey = {pa}\nAllowedIPs = {A}/32\nEndpoint = 192.0.2.1:1"
            );
            Peers::new(&config::parse(&conf).unwrap()).unwrap()
        };
        (Peers::new(&config::parse(&a).unwrap()).unwrap(), other(&kb), other(&kc))
    }

    #[test]
    fn a_peer_does_not_send_as_an_address_that_another_peer_holds_more_closely() {
        let (mut a, mut wide, mut narrow) = three("10.9.0.0/24", "10.9.0.2/32");
        // 10.9.0.2 is in the first peer's net, and a packet to it goes to
        // the second peer.
        let mut datagrams = sent(&mut wide, &ip("10.9.0.2", A));
        assert!(settle(&mut a, &mut wide, &mut datagrams, 2).0.is_empty());
        assert_eq!(a.dropped, Dropped { unknown: 0, refused: 0, disallowed: 1 });
        let mut datagrams = sent(&mut wide, &ip("10.9.0.3", A));
        assert_eq!(settle(&mut a, &mut wide, &mut datagrams, 2).0, [ip("10.9.0.3", A)]);
        let mut datagrams = sent(&mut narrow, &ip("10.9.0.2", A));
        assert_eq!(settle(&mut a, &mut narrow, &mut datagrams, 3).0, [ip("10.9.0.2", A)]);
        // The second peer has that one address and no other.
        let mut datagrams = sent(&mut narrow, &ip("10.9.0.3", A));
        assert!(settle(&mut a, &mut narrow, &mut datagrams, 3).0.is_empty());
        assert_eq!(a.dropped.disallowed, 2);
    }

    #[test]
    fn a_net_that_two_peers_have_is_the_later_one_s() {
        let (mut a, mut first, mut second) = three("10.9.0.2/32", "10.9.0.2/32");
        let mut datagrams = sent(&mut first, &ip(B, A));
        assert!(settle(&mut a, &mut first, &mut datagrams, 2).0.is_empty());
        let mut datagrams = sent(&mut second, &ip(B, A));
        assert_eq!(settle(&mut a, &mut second, &mut datagrams, 3).0, [ip(B, A)]);
        assert_eq!(a.route(&B.parse().unwrap()), Some(1));
    }

    /// Builds a small IPv6 packet from one address to another.
    fn ip6(src: &str, dst: &str) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 4, 253, 64];
        for addr in [src, dst] {
            p.extend(addr.parse::<std::net::Ipv6Addr>().unwrap().octets());
        }
        p.extend(b"data");
        p
    }

    #[test]
    fn a_source_that_no_peer_can_have_is_dropped() {
        // B is a gateway to A: every address is in its AllowedIPs.
        let ((ka, pa), (kb, pb)) = (key(1), key(2));
        let a = format!(
            "[Interface]\nPrivateKey = {ka}\nAddress = {A}, fd09::1\n\
             [Peer]\nPublicKey = {pb}\nAllowedIPs = 0.0.0.0/0, ::/0"
        );
        let b = format!(
            "[Interface]\nPrivateKey = {kb}\nAddress = {B}\n\
             [Peer]\nPublicKey = {pa}\nAllowedIPs = {A}/32, fd09::1/128\nEndpoint = 192.0.2.1:1"
        );
        let mut a = Peers::new(&config::parse(&a).unwrap()).unwrap();
        let mut b = Peers::new(&config::parse(&b).unwrap()).unwrap();
        let mut refused = 0;
        // The loopback address, an address of A, and addresses that are
        // the source of no packet.
        for src in ["127.0.0.1", "127.9.9.9", A, "224.0.0.1", "255.255.255.255", "0.0.0.0"] {
            let mut datagrams = sent(&mut b, &ip(src, A));
            assert!(settle(&mut a, &mut b, &mut datagrams, 2).0.is_empty(), "{src}");
            refused += 1;
            assert_eq!(a.dropped, Dropped { unknown: 0, refused: 0, disallowed: refused }, "{src}");
        }
        // And an IPv4 address in the dress of an IPv6 address, which
        // Ruby would take for the address of another peer.
        for src in ["::1", "fd09::1", "ff02::1", "::", "::ffff:10.9.0.2", "::ffff:127.0.0.1"] {
            let mut datagrams = sent(&mut b, &ip6(src, "fd09::1"));
            assert!(settle(&mut a, &mut b, &mut datagrams, 2).0.is_empty(), "{src}");
            refused += 1;
            assert_eq!(a.dropped.disallowed, refused, "{src}");
        }
        for packet in [ip(B, A), ip("192.0.2.7", A), ip6("fd09::2", "fd09::1"), ip6("2001:db8::7", "fd09::1")] {
            let mut datagrams = sent(&mut b, &packet);
            assert_eq!(settle(&mut a, &mut b, &mut datagrams, 2).0, [packet]);
        }
    }

    #[test]
    fn what_no_peer_sent_is_dropped() {
        let (mut a, mut b) = pair();
        let mut datagrams = sent(&mut b, &ip(B, A));
        settle(&mut a, &mut b, &mut datagrams, 2);
        let mut replies = 0;
        assert_eq!(a.receive(b"not WireGuard", at(9), &mut |_, _| replies += 1), None);
        // This data packet names a session index that no peer of A holds.
        let mut stray = sent(&mut b, &ip(B, A)).pop_front().unwrap();
        stray[5] ^= 0xff;
        assert_eq!(a.receive(&stray, at(9), &mut |_, _| replies += 1), None);
        // This one names the right session, and its payload is damaged.
        let mut damaged = sent(&mut b, &ip(B, A)).pop_front().unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        assert_eq!(a.receive(&damaged, at(9), &mut |_, _| replies += 1), None);
        assert_eq!((&a.dropped, replies), (&Dropped { unknown: 2, refused: 1, disallowed: 0 }, 0));
        assert_eq!(a.list[0].endpoint, Some(at(2)), "none of the three moved the endpoint");
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

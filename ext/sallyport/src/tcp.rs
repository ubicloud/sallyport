//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end.

use crate::config::Config;
use crate::sys;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// Each direction of a connection has a buffer of this size. It is more
/// than 64 KiB so that smoltcp negotiates window scaling.
const TCP_BUF: usize = 256 * 1024;
/// A connection is dead when its peer has sent nothing for this long.
/// smoltcp counts the silence whether or not anything waits to be
/// acknowledged, so a connection has to ask a quiet peer to answer.
const TCP_TIMEOUT: Duration = Duration::from_secs(300);
/// A connection asks its peer for an ACK when the peer has been quiet for
/// this long.
const KEEP_ALIVE: Duration = Duration::from_secs(75);
/// An outbound connection takes one of this many local ports, of which
/// this is the first. They are the ports that IANA leaves for the purpose.
const FIRST_PORT: u16 = 49152;
const PORTS: u16 = 16384;

/// Every outbound connection's stream begins with one of these bytes.
pub mod status {
    pub const OK: u8 = 0;
    pub const REFUSED: u8 = 1;
    pub const TIMED_OUT: u8 = 2;
    pub const NO_ROUTE: u8 = 3;
    pub const NO_PORT: u8 = 4;
}

/// The stack's link is two queues of IP packets.
struct Link {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

impl Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

#[derive(PartialEq)]
enum Phase {
    /// The SYN is sent, and Ruby waits on its end for the status.
    Connecting(Instant),
    Open,
    /// The connection is closed to Ruby and has no descriptor. Its socket
    /// stays until it has sent what it owes the peer.
    Dead,
}

/// A step decides one of these for its connection.
enum Fate {
    Keep,
    /// Close our end of the pair. The TCP connection has ended by itself.
    Close,
    /// Close our end of the pair, and reset the TCP connection.
    Abort,
    Remove,
}

struct Conn {
    handle: SocketHandle,
    /// Our end of the pair, until the connection is closed to Ruby.
    fd: Option<OwnedFd>,
    phase: Phase,
    local_port: u16,
}

impl Conn {
    /// Returns our end of the pair as a system call takes it, or -1 if it
    /// is closed.
    fn raw(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }
}

pub struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    link: Link,
    conns: Vec<Conn>,
    local_ports: HashSet<u16>,
    addrs: Vec<IpAddr>,
    epoch: Instant,
}

impl Stack {
    pub fn new(cfg: &Config) -> Stack {
        let mut link = Link { rx: VecDeque::new(), tx: VecDeque::new(), mtu: cfg.mtu };
        let mut ic = IfaceConfig::new(HardwareAddress::Ip);
        ic.random_seed = u64::from_ne_bytes(sys::random());
        let mut iface = Interface::new(ic, &mut link, SInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            for addr in &cfg.addrs {
                let len = if addr.is_ipv4() { 32 } else { 128 };
                addrs.push(IpCidr::new(IpAddress::from(*addr), len)).expect("the parser allows no more than fit");
            }
        });
        // The link has no next hop: a packet goes to the peer whose
        // AllowedIPs hold its destination. smoltcp wants a route before it
        // will send, so it is given one for every destination.
        iface.routes_mut().add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1)).expect("room for two routes");
        iface.routes_mut().add_default_ipv6_route(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)).expect("room for two routes");
        Stack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            link,
            conns: Vec::new(),
            local_ports: HashSet::new(),
            addrs: cfg.addrs.clone(),
            epoch: Instant::now(),
        }
    }

    fn now(&self) -> SInstant {
        SInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    /// Queues an IP packet that arrived for the stack.
    pub fn receive(&mut self, packet: Vec<u8>) {
        self.link.rx.push_back(packet);
    }

    /// Returns the next IP packet that the stack wants sent.
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        self.link.tx.pop_front()
    }

    /// Tells Ruby, on its descriptor, why a connection was not begun, and
    /// closes our end.
    pub fn refuse(fd: OwnedFd, code: u8) {
        sys::send(fd.as_raw_fd(), &[code]);
    }

    /// Begins a connection to a TCP port for the socket pair whose end is
    /// `fd`. Ruby learns the outcome from the first byte that it reads
    /// from the pair.
    pub fn connect(&mut self, fd: OwnedFd, addr: IpAddr, port: u16) {
        // A connection leaves from an address of the destination's family.
        // smoltcp does not see to that for IPv6: with no address to use,
        // it would send from the loopback address.
        if !self.addrs.iter().any(|ours| ours.is_ipv4() == addr.is_ipv4()) {
            return Stack::refuse(fd, status::NO_ROUTE);
        }
        // The search for a free port begins at a random one.
        let first = u16::from_ne_bytes(sys::random());
        let mut ports = (0..PORTS).map(|n| FIRST_PORT + first.wrapping_add(n) % PORTS);
        let Some(local) = ports.find(|port| self.local_ports.insert(*port)) else {
            return Stack::refuse(fd, status::NO_PORT);
        };
        let mut s =
            tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
        s.set_timeout(Some(SDuration::from_millis(TCP_TIMEOUT.as_millis() as u64)));
        s.set_keep_alive(Some(SDuration::from_millis(KEEP_ALIVE.as_millis() as u64)));
        let from = IpListenEndpoint { addr: None, port: local };
        // smoltcp refuses the unspecified address.
        if s.connect(self.iface.context(), (IpAddress::from(addr), port), from).is_err() {
            self.local_ports.remove(&local);
            return Stack::refuse(fd, status::NO_ROUTE);
        }
        let handle = self.sockets.add(s);
        self.conns.push(Conn { handle, fd: Some(fd), phase: Phase::Connecting(Instant::now()), local_port: local });
    }

    /// Takes in the packets that arrived, has every socket send what it
    /// has to send, and then moves each connection on. Returns whether a
    /// connection moved, in which case the stack has more to do.
    pub fn turn(&mut self) -> bool {
        let now = self.now();
        self.iface.poll(now, &mut self.link, &mut self.sockets);
        self.pump()
    }

    /// Returns how long the stack can wait before its next timer.
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let now = self.now();
        self.iface.poll_delay(now, &self.sockets).map(|d| Duration::from_micros(d.total_micros()))
    }

    /// Moves every connection as far as it will go.
    fn pump(&mut self) -> bool {
        let mut moved = false;
        let mut i = 0;
        while i < self.conns.len() {
            let c = &mut self.conns[i];
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            let (m, fate) = step(c, s);
            moved |= m;
            match fate {
                Fate::Keep => {}
                Fate::Close | Fate::Abort => {
                    // Ruby's part is over. An aborted socket has a reset
                    // to send, and must stay until it has sent it.
                    if matches!(fate, Fate::Abort) {
                        s.abort();
                    }
                    c.fd = None;
                    c.phase = Phase::Dead;
                    moved = true;
                }
                Fate::Remove => {
                    let c = self.conns.swap_remove(i);
                    self.sockets.remove(c.handle);
                    self.local_ports.remove(&c.local_port);
                    continue;
                }
            }
            i += 1;
        }
        moved
    }

    /// Adds to `fds` the descriptor of each connection that poll should
    /// watch.
    pub fn poll_fds(&self, fds: &mut Vec<libc::pollfd>) {
        // poll reports a hangup whether asked or not. So a descriptor with
        // no events asked of it is watched for Ruby closing its end, and
        // for nothing else.
        for c in self.conns.iter().filter(|c| c.phase != Phase::Dead) {
            fds.push(libc::pollfd { fd: c.raw(), events: 0, revents: 0 });
        }
    }
}

/// Moves one connection as far as it will go. Returns whether it moved,
/// and what becomes of it.
fn step(c: &mut Conn, s: &mut tcp::Socket) -> (bool, Fate) {
    match c.phase {
        Phase::Dead => {
            // smoltcp forgets the peer once it has no more to send it.
            let sent = s.state() == tcp::State::Closed && s.remote_endpoint().is_none();
            (false, if sent { Fate::Remove } else { Fate::Keep })
        }
        // Ruby closed its end. In Phase::Connecting, it gave up waiting.
        _ if sys::hung_up(c.raw()) => (true, Fate::Abort),
        Phase::Connecting(since) => match s.state() {
            // The peer answers a SYN with a bare SYN if it was connecting
            // to us at the same moment, and the handshake is not over.
            tcp::State::SynSent | tcp::State::SynReceived => (false, Fate::Keep),
            tcp::State::Closed => {
                // smoltcp does not say whether a reset or its timeout
                // closed the socket, so the time taken has to.
                let late = since.elapsed() + Duration::from_secs(1) >= TCP_TIMEOUT;
                sys::send(c.raw(), &[if late { status::TIMED_OUT } else { status::REFUSED }]);
                (true, Fate::Close)
            }
            _ => {
                sys::send(c.raw(), &[status::OK]);
                c.phase = Phase::Open;
                (true, Fate::Keep)
            }
        },
        // Nothing carries the connection's bytes yet.
        Phase::Open if s.state() == tcp::State::Closed => (true, Fate::Close),
        Phase::Open => (false, Fate::Keep),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    const A: &str = "10.9.0.1";
    const B: &str = "10.9.0.2";

    fn stack(addr: &str) -> Stack {
        let key = crate::keys::encode(&[1; 32]);
        Stack::new(&config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {addr}")).unwrap())
    }

    /// Begins a connection, and returns Ruby's end of its pair.
    fn connect(stack: &mut Stack, addr: &str, port: u16) -> UnixStream {
        let (ours, theirs) = sys::socketpair().unwrap();
        stack.connect(ours, addr.parse().unwrap(), port);
        let theirs = UnixStream::from(theirs);
        theirs.set_nonblocking(true).unwrap();
        theirs
    }

    /// Returns what Ruby can read now, and whether the stream has ended.
    fn read(ruby: &mut UnixStream) -> (Vec<u8>, bool) {
        let mut all = Vec::new();
        let mut buf = [0; 4096];
        loop {
            match ruby.read(&mut buf) {
                Ok(0) => return (all, true),
                Ok(n) => all.extend(&buf[..n]),
                Err(_) => return (all, false),
            }
        }
    }

    /// Carries packets between two stacks until neither has more to do.
    fn settle(a: &mut Stack, b: &mut Stack) {
        loop {
            let mut moved = a.turn() | b.turn();
            while let Some(packet) = a.transmit() {
                b.receive(packet);
                moved = true;
            }
            while let Some(packet) = b.transmit() {
                a.receive(packet);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    /// Says whether an IPv4 packet is a TCP reset.
    fn is_reset(packet: &[u8]) -> bool {
        packet[9] == 6 && packet[20 + 13] & 0x04 != 0
    }

    #[test]
    fn a_port_where_nothing_listens_refuses() {
        let (mut a, mut b) = (stack(A), stack(B));
        let mut ruby = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::REFUSED], true));
        assert!(a.conns.is_empty() && a.local_ports.is_empty());
    }

    #[test]
    fn an_attempt_that_ruby_gives_up_is_reset() {
        let mut a = stack(A);
        let ruby = connect(&mut a, B, 7);
        a.turn();
        assert!(!is_reset(&a.transmit().unwrap()), "the SYN goes out");
        drop(ruby);
        while a.turn() {}
        assert!(is_reset(&a.transmit().unwrap()));
        assert!(a.conns.is_empty() && a.local_ports.is_empty());
    }

    #[test]
    fn an_address_that_the_tunnel_cannot_connect_from_has_no_route() {
        for (ours, theirs) in [(A, "fd09::2"), ("fd09::1", B), (A, "0.0.0.0")] {
            let mut a = stack(ours);
            let mut ruby = connect(&mut a, theirs, 7);
            assert_eq!(read(&mut ruby), (vec![status::NO_ROUTE], true));
            assert!(a.conns.is_empty() && a.local_ports.is_empty());
        }
    }

    #[test]
    fn each_connection_has_a_local_port_until_none_is_left() {
        let mut a = stack(A);
        let rubies: Vec<UnixStream> = (0..3).map(|_| connect(&mut a, B, 7)).collect();
        let ports: HashSet<u16> = a.conns.iter().map(|c| c.local_port).collect();
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().all(|port| *port >= FIRST_PORT));
        drop(rubies);
        a.local_ports.extend(FIRST_PORT..=u16::MAX);
        let mut ruby = connect(&mut a, B, 7);
        assert_eq!(read(&mut ruby), (vec![status::NO_PORT], true));
    }
}

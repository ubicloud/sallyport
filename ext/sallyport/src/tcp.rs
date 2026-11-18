//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end.

use crate::config::Config;
use crate::packet::{rst, syn};
use crate::sys::{self, Sent};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

/// The tunnel's thread first sends one of these bytes on the pair of an
/// outbound connection, and on the pair of a listener.
pub mod status {
    pub const OK: u8 = 0;
    pub const REFUSED: u8 = 1;
    pub const TIMED_OUT: u8 = 2;
    pub const NO_ROUTE: u8 = 3;
    pub const NO_PORT: u8 = 4;
    pub const IN_USE: u8 = 5;
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
    /// The socket waits for a SYN, or for the handshake that the SYN
    /// began. There is no socket pair yet.
    Listening,
    /// The connection is established, and its listener has yet to send
    /// Ruby its end of the pair.
    Accepting,
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
    /// Our end of the pair. An inbound connection has none until it is
    /// established, and no connection has one once it is closed to Ruby.
    fd: Option<OwnedFd>,
    phase: Phase,
    /// The port of the listener that has yet to send Ruby this inbound
    /// connection.
    listener: Option<u16>,
    /// Ruby's end of the pair, until the listener has sent it.
    theirs: Option<OwnedFd>,
    /// The local port that an outbound connection took.
    local_port: Option<u16>,
}

impl Conn {
    fn new(handle: SocketHandle, fd: Option<OwnedFd>, phase: Phase) -> Conn {
        Conn { handle, fd, phase, listener: None, theirs: None, local_port: None }
    }

    /// Returns our end of the pair as a system call takes it, or -1 if
    /// there is none.
    fn raw(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }
}

struct Listener {
    port: u16,
    /// Our end of the pair on which Ruby is sent each connection.
    ctl: OwnedFd,
    backlog: usize,
    /// How many connections Ruby has been sent and has not yet accepted.
    unaccepted: usize,
}

impl Listener {
    /// Counts the connections that Ruby has accepted since the last call.
    /// Ruby answers each with a message.
    fn credit(&mut self) {
        while sys::read(self.ctl.as_raw_fd(), &mut [0; 16]) > 0 {
            self.unaccepted = self.unaccepted.saturating_sub(1);
        }
    }
}

pub struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    link: Link,
    conns: Vec<Conn>,
    listeners: Vec<Listener>,
    local_ports: HashSet<u16>,
    addrs: Vec<IpAddr>,
    epoch: Instant,
}

fn socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
    s.set_timeout(Some(SDuration::from_millis(TCP_TIMEOUT.as_millis() as u64)));
    s.set_keep_alive(Some(SDuration::from_millis(KEEP_ALIVE.as_millis() as u64)));
    s
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
            listeners: Vec::new(),
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
        let mut s = socket();
        let from = IpListenEndpoint { addr: None, port: local };
        // smoltcp refuses the unspecified address.
        if s.connect(self.iface.context(), (IpAddress::from(addr), port), from).is_err() {
            self.local_ports.remove(&local);
            return Stack::refuse(fd, status::NO_ROUTE);
        }
        let handle = self.sockets.add(s);
        let phase = Phase::Connecting(Instant::now());
        self.conns.push(Conn { local_port: Some(local), ..Conn::new(handle, Some(fd), phase) });
    }

    /// Listens on a TCP port. `ctl` is our end of the pair on which Ruby
    /// is told whether the port was free, and is then sent each
    /// connection.
    pub fn listen(&mut self, ctl: OwnedFd, port: u16, backlog: usize) {
        // Ruby may have closed a listener on this port a moment ago.
        self.reap();
        if self.listeners.iter().any(|l| l.port == port) {
            return Stack::refuse(ctl, status::IN_USE);
        }
        sys::send(ctl.as_raw_fd(), &[status::OK]);
        self.listeners.push(Listener { port, ctl, backlog, unaccepted: 0 });
    }

    /// Stops the listening on each port whose listener Ruby has closed.
    /// Returns whether there was one.
    fn reap(&mut self) -> bool {
        let before = self.listeners.len();
        let mut i = 0;
        while i < self.listeners.len() {
            let port = self.listeners[i].port;
            if !sys::ended(self.listeners[i].ctl.as_raw_fd()) {
                i += 1;
                continue;
            }
            // A connection that Ruby was not sent loses its listener here,
            // and is reset at its next step.
            for c in self.conns.iter_mut().filter(|c| c.listener == Some(port)) {
                c.listener = None;
            }
            self.listeners.swap_remove(i);
        }
        self.listeners.len() < before
    }

    /// Makes a socket for a SYN to a port, if the port is listened on and
    /// its listener has room. A listener has room until the connections
    /// that Ruby has not accepted, and the handshakes under way, are as
    /// many as its backlog. smoltcp keeps no queue of them: a socket takes
    /// one connection.
    fn socket_for(&mut self, port: u16) -> Option<SocketHandle> {
        let l = self.listeners.iter_mut().find(|l| l.port == port)?;
        // Ruby may have closed the listener a moment ago.
        if sys::ended(l.ctl.as_raw_fd()) {
            return None;
        }
        l.credit();
        let pending = l.unaccepted + self.conns.iter().filter(|c| c.listener == Some(port)).count();
        let mut s = socket();
        if pending >= l.backlog || s.listen(port).is_err() {
            return None;
        }
        let handle = self.sockets.add(s);
        self.conns.push(Conn { listener: Some(port), ..Conn::new(handle, None, Phase::Listening) });
        Some(handle)
    }

    /// Says whether a socket already has the connection between these two
    /// ends.
    fn has(&self, from: SocketAddr, to: SocketAddr) -> bool {
        let (from, to) = (Some(IpEndpoint::from(from)), Some(IpEndpoint::from(to)));
        self.conns
            .iter()
            .map(|c| self.sockets.get::<tcp::Socket>(c.handle))
            .any(|s| s.state() != tcp::State::Listen && s.remote_endpoint() == from && s.local_endpoint() == to)
    }

    /// Gives the stack the packets that arrived. They go in one at a
    /// time, so that each SYN of a burst finds a socket of its own
    /// listening.
    fn ingress(&mut self) {
        while let Some(packet) = self.link.rx.front() {
            // A SYN arrives twice when its answer was lost or was slow.
            // smoltcp gives a SYN to the first socket that will take it,
            // and a listening socket takes any. So the second copy gets no
            // socket, and is left to the one that the first copy got.
            let fresh = syn(packet).filter(|(from, to)| !self.has(*from, *to));
            let reset = rst(packet);
            let made = fresh.and_then(|(_, to)| self.socket_for(to.port()));
            let now = self.now();
            self.iface.poll_ingress_single(now, &mut self.link, &mut self.sockets);
            // A socket that listens now would take the next SYN to the
            // port, whatever connection that one belonged to, and it would
            // hold a place in the backlog. It is the socket that was made
            // for this SYN, if smoltcp gave the SYN to another. Or the
            // packet reset a handshake that the socket had answered:
            // smoltcp does not close such a socket, and has it listen
            // again.
            if made.is_some() || reset {
                self.unlisten();
            }
        }
    }

    /// Removes each socket that listens, and its connection.
    fn unlisten(&mut self) {
        let sockets = &mut self.sockets;
        self.conns.retain(|c| {
            let listens =
                c.phase == Phase::Listening && sockets.get::<tcp::Socket>(c.handle).state() == tcp::State::Listen;
            if listens {
                sockets.remove(c.handle);
            }
            !listens
        });
    }

    /// Takes in the packets that arrived, has every socket send what it
    /// has to send, and then moves each connection on. Returns whether a
    /// connection moved, in which case the stack has more to do.
    pub fn turn(&mut self) -> bool {
        self.ingress();
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
            let (m, fate) = step(c, s, &mut self.listeners);
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
                    c.theirs = None;
                    c.listener = None;
                    c.phase = Phase::Dead;
                    moved = true;
                }
                Fate::Remove => {
                    let c = self.conns.swap_remove(i);
                    self.sockets.remove(c.handle);
                    if let Some(port) = c.local_port {
                        self.local_ports.remove(&port);
                    }
                    continue;
                }
            }
            i += 1;
        }
        for l in &mut self.listeners {
            l.credit();
        }
        moved | self.reap()
    }

    /// Adds to `fds` each descriptor that poll should watch for the
    /// connections and the listeners.
    pub fn poll_fds(&self, fds: &mut Vec<libc::pollfd>) {
        // A listener is watched for Ruby accepting a connection and for
        // Ruby closing it.
        for l in &self.listeners {
            fds.push(libc::pollfd { fd: l.ctl.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        // poll reports a hangup whether asked or not. So a descriptor with
        // no events asked of it is watched for Ruby closing its end, and
        // for nothing else.
        for c in self.conns.iter().filter(|c| matches!(c.phase, Phase::Connecting(_) | Phase::Open)) {
            fds.push(libc::pollfd { fd: c.raw(), events: 0, revents: 0 });
        }
    }
}

/// Moves one connection as far as it will go. Returns whether it moved,
/// and what becomes of it.
fn step(c: &mut Conn, s: &mut tcp::Socket, listeners: &mut [Listener]) -> (bool, Fate) {
    match c.phase {
        Phase::Dead => {
            // smoltcp forgets the peer once it has no more to send it.
            let sent = s.state() == tcp::State::Closed && s.remote_endpoint().is_none();
            (false, if sent { Fate::Remove } else { Fate::Keep })
        }
        // Ruby closed its end. In Phase::Connecting, it gave up waiting.
        Phase::Connecting(_) | Phase::Open if sys::hung_up(c.raw()) => (true, Fate::Abort),
        // Ruby closed the listener.
        Phase::Listening | Phase::Accepting if c.listener.is_none() => (true, Fate::Abort),
        Phase::Listening => match s.state() {
            tcp::State::Listen | tcp::State::SynReceived => (false, Fate::Keep),
            // The peer left the handshake unfinished, or it finished the
            // handshake and reset the connection at once.
            tcp::State::Closed => (true, Fate::Close),
            _ => match sys::socketpair(libc::SOCK_STREAM) {
                Ok((ours, theirs)) => {
                    c.fd = Some(ours);
                    c.theirs = Some(theirs);
                    c.phase = Phase::Accepting;
                    (true, Fate::Keep)
                }
                // The system has no descriptors to spare.
                Err(_) => (true, Fate::Abort),
            },
        },
        Phase::Accepting => {
            let listener = listeners.iter_mut().find(|l| Some(l.port) == c.listener);
            // The peer may have reset the connection already.
            let (Some(l), Some(from), Some(theirs)) = (listener, s.remote_endpoint(), &c.theirs) else {
                return (true, Fate::Abort);
            };
            let message = format!("{} {}", from.addr, from.port);
            match sys::send_fd(l.ctl.as_raw_fd(), message.as_bytes(), theirs.as_raw_fd()) {
                Sent::Ok => {
                    c.theirs = None;
                    l.unaccepted += 1;
                    c.listener = None;
                    c.phase = Phase::Open;
                    (true, Fate::Keep)
                }
                // The pair has no room, and the next turn tries again.
                Sent::Full => (false, Fate::Keep),
                Sent::Gone => (true, Fate::Abort),
            }
        }
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
    use std::os::unix::net::{UnixDatagram, UnixStream};

    const A: &str = "10.9.0.1";
    const B: &str = "10.9.0.2";

    fn stack(addr: &str) -> Stack {
        let key = crate::keys::encode(&[1; 32]);
        Stack::new(&config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {addr}")).unwrap())
    }

    /// Begins a connection, and returns Ruby's end of its pair.
    fn connect(stack: &mut Stack, addr: &str, port: u16) -> UnixStream {
        let (ours, theirs) = sys::socketpair(libc::SOCK_STREAM).unwrap();
        stack.connect(ours, addr.parse().unwrap(), port);
        let theirs = UnixStream::from(theirs);
        theirs.set_nonblocking(true).unwrap();
        theirs
    }

    /// Listens on a port, and returns Ruby's end of the listener's pair.
    /// std has no type for a socket of the pair's kind, and UnixDatagram
    /// sends and receives a message on one well enough.
    fn listen(stack: &mut Stack, port: u16, backlog: usize) -> UnixDatagram {
        let (ours, theirs) = sys::socketpair(libc::SOCK_SEQPACKET).unwrap();
        stack.listen(ours, port, backlog);
        let theirs = UnixDatagram::from(theirs);
        theirs.set_nonblocking(true).unwrap();
        theirs
    }

    /// Returns the next message on a listener's pair. The descriptor that
    /// came with it is not taken, and so is closed.
    fn message(ruby: &UnixDatagram) -> Option<Vec<u8>> {
        let mut buf = [0; 64];
        ruby.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
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
        let ports: HashSet<u16> = a.conns.iter().filter_map(|c| c.local_port).collect();
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().all(|port| *port >= FIRST_PORT));
        drop(rubies);
        a.local_ports.extend(FIRST_PORT..=u16::MAX);
        let mut ruby = connect(&mut a, B, 7);
        assert_eq!(read(&mut ruby), (vec![status::NO_PORT], true));
    }

    #[test]
    fn a_listener_is_sent_each_connection() {
        let (mut a, mut b) = (stack(A), stack(B));
        let listener = listen(&mut b, 7, 4);
        assert_eq!(message(&listener), Some(vec![status::OK]));
        let mut ruby = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert!(b.conns.len() == 1 && b.conns[0].phase == Phase::Open && b.listeners[0].unaccepted == 1);
        let from = format!("{A} {}", a.conns[0].local_port.unwrap());
        assert_eq!(message(&listener), Some(from.into_bytes()));
        // The message was read here without its descriptor. So the pair's
        // other end is closed, and the connection is reset.
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![], true));
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    #[test]
    fn a_port_has_one_listener_at_a_time() {
        let mut b = stack(B);
        let first = listen(&mut b, 7, 4);
        let second = listen(&mut b, 7, 4);
        assert_eq!(message(&second), Some(vec![status::IN_USE]));
        assert_eq!(message(&second), Some(vec![]), "and its stream ends");
        drop(first);
        assert_eq!(message(&listen(&mut b, 7, 4)), Some(vec![status::OK]));
        assert_eq!(b.listeners.len(), 1);
    }

    #[test]
    fn a_listener_that_ruby_can_no_longer_answer_on_is_closed() {
        let mut b = stack(B);
        let listener = listen(&mut b, 7, 4);
        // Ruby shuts down its writing and keeps the descriptor. It could
        // answer for no connection, and poll would report the end of what
        // it writes for ever.
        listener.shutdown(std::net::Shutdown::Write).unwrap();
        b.turn();
        assert!(b.listeners.is_empty());
    }

    #[test]
    fn no_more_than_the_backlog_wait_to_be_accepted() {
        let (mut a, mut b) = (stack(A), stack(B));
        let listener = listen(&mut b, 7, 2);
        // The three SYNs arrive in one burst.
        let mut rubies: Vec<UnixStream> = (0..3).map(|_| connect(&mut a, B, 7)).collect();
        settle(&mut a, &mut b);
        let statuses: Vec<u8> = rubies.iter_mut().map(|ruby| read(ruby).0[0]).collect();
        assert_eq!(statuses, [status::OK, status::OK, status::REFUSED]);
        // Ruby accepts one, and there is room for another.
        listener.send(&[0]).unwrap();
        let mut ruby = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert_eq!(b.listeners[0].unaccepted, 2);
    }

    #[test]
    fn a_closed_listener_resets_a_handshake_that_it_began() {
        let (mut a, mut b) = (stack(A), stack(B));
        let listener = listen(&mut b, 7, 4);
        let _ruby = connect(&mut a, B, 7);
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert!(!is_reset(&b.transmit().unwrap()), "the SYN is answered");
        drop(listener);
        while b.turn() {}
        assert!(is_reset(&b.transmit().unwrap()));
        assert!(b.conns.is_empty() && b.listeners.is_empty());
        // A SYN now finds nothing listening.
        let mut ruby = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby).0, [status::REFUSED]);
    }

    #[test]
    fn a_syn_that_arrives_twice_makes_one_connection() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 4);
        // An earlier connection holds the first place among B's sockets.
        let earlier = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        let mut ruby = connect(&mut a, B, 7);
        a.turn();
        let syn = a.transmit().unwrap();
        b.receive(syn.clone());
        b.turn();
        let answer = b.transmit().unwrap();
        // The earlier connection ends, and its place is free. A socket
        // made now would stand before the one that the SYN got, and
        // smoltcp would give it the second copy.
        drop(earlier);
        while a.turn() {}
        b.receive(a.transmit().unwrap());
        while b.turn() {}
        assert_eq!(b.conns.len(), 1);
        b.receive(syn);
        b.turn();
        assert!(b.conns.len() == 1 && b.transmit().is_none(), "the second copy is passed over");
        a.receive(answer);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert!(b.conns.len() == 1 && b.conns[0].phase == Phase::Open);
    }

    #[test]
    fn a_handshake_that_its_peer_resets_leaves_no_socket() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 4);
        let ruby = connect(&mut a, B, 7);
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert!(!is_reset(&b.transmit().unwrap()), "the SYN is answered");
        // The answer is lost, and Ruby gives the attempt up.
        drop(ruby);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    #[test]
    fn a_socket_whose_handshake_was_reset_takes_no_other_syn() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 4);
        // B answers two SYNs, and neither answer has arrived.
        let first = connect(&mut a, B, 7);
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert!(!is_reset(&b.transmit().unwrap()), "the first SYN is answered");
        let mut ruby = connect(&mut a, B, 7);
        a.turn();
        let syn = a.transmit().unwrap();
        b.receive(syn.clone());
        b.turn();
        let answer = b.transmit().unwrap();
        // Ruby gives the first attempt up, and A resets it. smoltcp has
        // B's first socket listen again. It stands before the second, and
        // would take a second copy of the second SYN. The reset and the
        // copy arrive together.
        drop(first);
        while a.turn() {}
        let reset = a.transmit().unwrap();
        assert!(is_reset(&reset));
        b.receive(reset);
        b.receive(syn);
        b.turn();
        assert!(b.conns.len() == 1 && b.transmit().is_none(), "the second copy is passed over");
        a.receive(answer);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert!(b.conns.len() == 1 && b.conns[0].phase == Phase::Open);
    }
}

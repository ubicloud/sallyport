//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end, and moves bytes between it and the buffers of the TCP
//! socket. The buffers of both are bounded, so each direction has flow
//! control from end to end.

use crate::config::Config;
use crate::packet::{rst, syn};
use crate::sys::{self, Sent};
use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write;
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
/// A closed connection's socket stays this long to acknowledge the
/// peer's FIN. smoltcp delays an ACK by 10 ms at most.
const LINGER: Duration = Duration::from_millis(if cfg!(test) { 20 } else { 500 });
/// The retransmission timer waits this long at the least for a segment
/// to be acknowledged. smoltcp's waits a second by default, as RFC 6298
/// advises, and that of Linux waits 200 ms. A peer may delay an ACK for
/// nearly as long, so a shorter wait would send again what was not lost.
const MIN_RTO: Duration = Duration::from_millis(200);
/// A connection that Ruby has closed is given this long to hear the
/// peer's FIN, once the peer has acknowledged ours. Linux gives as long.
const FIN_WAIT: Duration = Duration::from_secs(60);
/// smoltcp delays an ACK for this long at the most.
const ACK_DELAY: Duration = Duration::from_millis(10);
/// A connection that has ended is given this long to send its last ACK
/// when the tunnel is closing, which is twice smoltcp's longest delay.
const LAST_ACK: Duration = Duration::from_millis(20);
/// One turn of the loop has the sockets send this many rounds of packets
/// at the most, with a packet from each socket in a round.
const EGRESS_ROUNDS: usize = 1024;
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
    Dead(Instant),
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
    /// Ruby has written all that it will: a read of our end returned 0,
    /// and our FIN follows the data.
    fd_eof: bool,
    /// The peer's FIN has been passed on to Ruby, as a shutdown of our
    /// end.
    rx_shut: bool,
    /// When poll first reported a hangup on our end. Either Ruby has
    /// closed its end, or each side has shut down its writing, which poll
    /// does not tell apart. In both cases Ruby has no more to say, and
    /// has been told all that it will be.
    app_gone: Option<Instant>,
    /// Since when the connection has waited for nothing but the peer's
    /// FIN: Ruby has left, and the peer has acknowledged our FIN.
    fin_wait: Option<Instant>,
    /// The tail holds what the peer sent last and Ruby has yet to be
    /// given, once that is taken out of the socket's buffer.
    tail: VecDeque<u8>,
    /// The tunnel is closing, and the connection is treated as if Ruby
    /// had closed its end.
    orphan: bool,
}

impl Conn {
    fn new(handle: SocketHandle, fd: Option<OwnedFd>, phase: Phase) -> Conn {
        Conn {
            handle,
            fd,
            phase,
            listener: None,
            theirs: None,
            local_port: None,
            fd_eof: false,
            rx_shut: false,
            app_gone: None,
            fin_wait: None,
            tail: VecDeque::new(),
            orphan: false,
        }
    }

    /// Returns our end of the pair as a system call takes it, or -1 if
    /// there is none.
    fn raw(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }
}

/// A SYN to a port meets one of these.
enum Welcome {
    /// Nothing listens on the port, and smoltcp resets the SYN.
    Nobody,
    /// The listener has no room for another connection.
    Full,
    /// The listener made this socket for the SYN.
    Socket(SocketHandle),
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
    // The socket pair has already gathered what Ruby wrote, and a key
    // typed into an interactive session must not wait for an ACK.
    s.set_nagle_enabled(false);
    // smoltcp has no congestion control unless one is chosen: it sends
    // as much as the peer's window takes, whatever the path can carry.
    s.set_congestion_control(tcp::CongestionControl::Cubic);
    s.set_min_rto(SDuration::from_millis(MIN_RTO.as_millis() as u64));
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
    fn welcome(&mut self, port: u16) -> Welcome {
        let Some(l) = self.listeners.iter_mut().find(|l| l.port == port) else { return Welcome::Nobody };
        // Ruby may have closed the listener a moment ago.
        if sys::ended(l.ctl.as_raw_fd()) {
            return Welcome::Nobody;
        }
        l.credit();
        let pending = l.unaccepted + self.conns.iter().filter(|c| c.listener == Some(port)).count();
        let mut s = socket();
        if pending >= l.backlog || s.listen(port).is_err() {
            return Welcome::Full;
        }
        let handle = self.sockets.add(s);
        self.conns.push(Conn { listener: Some(port), ..Conn::new(handle, None, Phase::Listening) });
        Welcome::Socket(handle)
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
            let made = match fresh.map(|(_, to)| self.welcome(to.port())) {
                // smoltcp would reset a SYN that finds no socket, and its
                // sender would take that to mean that nothing listens. A
                // SYN that the backlog has no room for is dropped, as
                // Linux drops it, and its sender tries again.
                Some(Welcome::Full) => {
                    self.link.rx.pop_front();
                    continue;
                }
                Some(Welcome::Socket(handle)) => Some(handle),
                Some(Welcome::Nobody) | None => None,
            };
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

    /// Returns how many connections there are: those that the stack is
    /// making, and those that are made and have not ended.
    pub fn connections(&self) -> usize {
        self.conns.iter().filter(|c| !matches!(c.phase, Phase::Listening | Phase::Dead(_))).count()
    }

    /// Describes every connection, each in two lines. The first is what
    /// the stack knows of it. The second is smoltcp's account of the
    /// socket, without the bytes in its buffers.
    pub fn describe(&self, text: &mut String) {
        for c in &self.conns {
            let phase = match c.phase {
                Phase::Connecting(_) => "connecting",
                Phase::Listening => "listening",
                Phase::Accepting => "accepting",
                Phase::Open => "open",
                Phase::Dead(_) => "dead",
            };
            let s = self.sockets.get::<tcp::Socket>(c.handle);
            let end = |end: Option<IpEndpoint>| end.map_or("-".into(), |end| end.to_string());
            let _ = writeln!(
                text,
                "{phase} {} to {}: {}, {} bytes to send and {} to give Ruby, {} waiting in the pair{}{}{}",
                end(s.local_endpoint()),
                end(s.remote_endpoint()),
                s.state(),
                s.send_queue(),
                s.recv_queue() + c.tail.len(),
                sys::readable(c.raw()),
                if c.fd_eof { ", Ruby has ended its stream" } else { "" },
                if c.rx_shut { ", the peer has ended its stream" } else { "" },
                if c.app_gone.is_some() { ", Ruby is gone" } else { "" },
            );
            let mut detail = format!("{s:?}");
            while let Some(from) = detail.find("Owned([") {
                let to = detail[from..].find("])").map_or(detail.len(), |to| from + to + 2);
                detail.replace_range(from..to, "..");
            }
            let _ = writeln!(text, "  {detail}");
        }
    }

    /// Has every socket send what it has to send.
    pub fn poll(&mut self) {
        let now = self.now();
        // smoltcp's poll sends until no socket has more to send. A socket
        // whose timer did not move would keep it there for ever, so the
        // rounds are counted. What is left goes at the next turn.
        for _ in 0..EGRESS_ROUNDS {
            if self.iface.poll_egress(now, &mut self.link, &mut self.sockets) == PollResult::None {
                break;
            }
        }
    }

    /// Takes in the packets that arrived, has every socket send what it
    /// has to send, and then moves each connection on. Returns whether a
    /// connection moved, in which case the stack has more to do.
    pub fn turn(&mut self) -> bool {
        self.ingress();
        self.poll();
        self.pump()
    }

    /// Stops the listening, and leaves every connection as it would be if
    /// Ruby had closed its end. The tunnel is closing.
    pub fn orphan(&mut self) {
        self.listeners.clear();
        for c in &mut self.conns {
            // The next step resets a connection that Ruby was not sent,
            // or that is not yet established.
            c.listener = None;
            c.orphan = true;
            if c.phase == Phase::Open {
                // Ruby reads the end of its stream, and what the peer
                // sends from now on has nobody to read it.
                sys::shutdown_write(c.raw());
                c.app_gone = c.app_gone.or(Some(Instant::now()));
            }
        }
    }

    /// Says whether every connection has ended, and has had the time to
    /// send its last ACK.
    pub fn finished(&self) -> bool {
        self.conns.iter().all(|c| matches!(c.phase, Phase::Dead(since) if since.elapsed() >= LAST_ACK))
    }

    /// Resets every connection that has not ended. The resets leave at
    /// the next poll.
    pub fn abort(&mut self) {
        for c in self.conns.iter().filter(|c| !matches!(c.phase, Phase::Dead(_))) {
            self.sockets.get_mut::<tcp::Socket>(c.handle).abort();
        }
        // A socket that has just taken the peer's FIN may still delay its
        // ACK, and the next poll is the last. So the stack's clock is put
        // on by the delay, and the ACK leaves with the resets.
        self.epoch -= ACK_DELAY;
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
                    // Ruby's part is over. The socket has a reset or a
                    // last ACK to send, and must stay until it has sent it.
                    if matches!(fate, Fate::Abort) {
                        s.abort();
                    }
                    c.fd = None;
                    c.theirs = None;
                    c.listener = None;
                    c.phase = Phase::Dead(Instant::now());
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
        for c in &self.conns {
            let s = self.sockets.get::<tcp::Socket>(c.handle);
            // poll reports a hangup whether asked or not. So a descriptor
            // with no events asked of it is watched for Ruby closing its
            // end, and for nothing else.
            let events = match c.phase {
                Phase::Listening | Phase::Accepting | Phase::Dead(_) => continue,
                // Ruby may write before it has the status, and nothing
                // reads that yet. So poll is not asked whether there is
                // anything to read, for which it would return for ever.
                Phase::Connecting(_) => 0,
                Phase::Open => {
                    // The pair is read while the socket has room, and
                    // written while the socket has bytes for Ruby.
                    let read = if !c.fd_eof && s.can_send() { libc::POLLIN } else { 0 };
                    let write = if s.can_recv() || !c.tail.is_empty() { libc::POLLOUT } else { 0 };
                    // Once the hangup has been seen, poll would return
                    // for it for ever.
                    if read | write == 0 && c.app_gone.is_some() {
                        continue;
                    }
                    read | write
                }
            };
            fds.push(libc::pollfd { fd: c.raw(), events, revents: 0 });
        }
    }
}

/// Moves one connection as far as it will go. Returns whether it moved,
/// and what becomes of it.
fn step(c: &mut Conn, s: &mut tcp::Socket, listeners: &mut [Listener]) -> (bool, Fate) {
    match c.phase {
        Phase::Dead(since) => {
            let sent = match s.state() {
                // smoltcp forgets the peer once it has no more to send it.
                tcp::State::Closed => s.remote_endpoint().is_none(),
                // The peer's FIN is owed an ACK.
                _ => since.elapsed() >= LINGER,
            };
            (false, if sent { Fate::Remove } else { Fate::Keep })
        }
        // Ruby gave up waiting, and closed its end.
        Phase::Connecting(_) if c.orphan || sys::hung_up(c.raw()) => (true, Fate::Abort),
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
        Phase::Open => carry(c, s),
    }
}

/// Moves bytes each way for an open connection, and passes on the end of
/// each direction.
fn carry(c: &mut Conn, s: &mut tcp::Socket) -> (bool, Fate) {
    let mut moved = false;

    if !c.fd_eof && !s.may_send() {
        // The peer reset the connection, or it timed out.
        c.fd_eof = true;
    }
    let fd = c.raw();
    while !c.fd_eof && s.can_send() {
        // The bytes are read from the pair into the socket's buffer.
        match s.send(|buf| {
            let n = sys::read(fd, buf);
            (n.max(0) as usize, n)
        }) {
            Ok(n) if n > 0 => moved = true,
            Ok(0) => {
                c.fd_eof = true;
                moved = true;
            }
            // An orphan's pair is read until it is empty, and no more.
            Ok(sys::AGAIN) if c.orphan => {
                c.fd_eof = true;
                moved = true;
            }
            Ok(sys::AGAIN) => break,
            // Ruby closed its end with bytes from us unread.
            _ => return (true, Fate::Abort),
        }
    }
    // Our FIN follows what Ruby wrote, and it waits until the peer has
    // taken all of that. smoltcp does not send a FIN well behind data that
    // a shut window holds back. Its probe of the window can carry the FIN
    // with the last byte, and the timer of the probe then outlives the
    // data: smoltcp sends an ACK each time that it is asked, and its poll
    // never ends. And in LAST-ACK it passes over an ACK that acknowledges
    // nothing new, and so would learn that the window was open again only
    // when its next probe was answered.
    let fin_due = matches!(s.state(), tcp::State::Established | tcp::State::CloseWait);
    if fin_due && c.fd_eof && s.send_queue() == 0 {
        s.close();
        moved = true;
    }
    if c.app_gone.is_none() && sys::hung_up(fd) {
        c.app_gone = Some(Instant::now());
    }
    // The peer's time to end its stream begins when Ruby has left and the
    // peer has acknowledged our FIN, whichever comes later.
    if c.fin_wait.is_none() && c.app_gone.is_some() && s.state() == tcp::State::FinWait2 {
        c.fin_wait = Some(Instant::now());
    }

    // smoltcp clears a socket when it has been in TIME-WAIT for ten
    // seconds, and its receive buffer with it. So what Ruby has not been
    // given by then is taken out of the buffer as soon as the peer's FIN
    // has arrived, and Ruby is given it from here.
    if s.state() == tcp::State::TimeWait {
        while s.can_recv() {
            let tail = &mut c.tail;
            let _ = s.recv(|buf| {
                tail.extend(buf.iter());
                (buf.len(), ())
            });
        }
    }
    while !c.tail.is_empty() {
        match sys::send(fd, c.tail.as_slices().0) {
            n if n > 0 => {
                c.tail.drain(..n as usize);
                moved = true;
            }
            sys::AGAIN => break,
            _ => return (true, Fate::Abort),
        }
    }
    while s.can_recv() {
        match s.recv(|buf| {
            let n = sys::send(fd, buf);
            (n.max(0) as usize, n)
        }) {
            Ok(n) if n > 0 => moved = true,
            Ok(sys::AGAIN) => break,
            // Ruby closed its end with bytes still to come.
            _ => return (true, Fate::Abort),
        }
    }
    if !c.rx_shut && !s.may_recv() && !s.can_recv() && c.tail.is_empty() {
        // The peer will send no more, and Ruby has been given all of it.
        sys::shutdown_write(fd);
        c.rx_shut = true;
        moved = true;
    }

    // An orphan is a connection that nobody is left to use on Ruby's side.
    let orphaned = c.app_gone.map(|since| since.elapsed());
    let waited = c.fin_wait.map(|since| since.elapsed());
    let fate = match s.state() {
        tcp::State::Closed | tcp::State::TimeWait if c.fd_eof && c.rx_shut => Fate::Close,
        // The peer has all that Ruby wrote, and is given a while to end
        // its stream too. What it sends in that time is reset above, for
        // want of anyone to read it. A tunnel that is closing does not
        // wait.
        tcp::State::FinWait2 if c.orphan || waited.is_some_and(|age| age >= FIN_WAIT) => Fate::Abort,
        // TCP waits for as long as the peer answers, and a peer may hold
        // its window shut for ever, or take a byte at a time. An orphan is
        // not kept that long: it has as long as a silent peer is given.
        _ if orphaned.is_some_and(|age| age >= TCP_TIMEOUT) => Fate::Abort,
        _ => Fate::Keep,
    };
    (moved, fate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::FromRawFd;
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

    /// Carries packets between two stacks until neither has more to do,
    /// and then for as long as smoltcp may delay an ACK.
    fn settle(a: &mut Stack, b: &mut Stack) {
        let mut quiet = 0;
        while quiet < 2 {
            let mut moved = a.turn() | b.turn();
            while let Some(packet) = a.transmit() {
                b.receive(packet);
                moved = true;
            }
            while let Some(packet) = b.transmit() {
                a.receive(packet);
                moved = true;
            }
            if moved {
                quiet = 0;
            } else {
                quiet += 1;
                std::thread::sleep(Duration::from_millis(12));
            }
        }
    }

    /// Takes the next connection from a listener's pair, and returns
    /// Ruby's end of it.
    fn accept(listener: &UnixDatagram) -> UnixStream {
        let (mut from, mut control) = ([0u8; 64], [0u64; 4]);
        let mut iov = libc::iovec { iov_base: from.as_mut_ptr().cast(), iov_len: from.len() };
        let fd = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            assert!(libc::recvmsg(listener.as_raw_fd(), &raw mut msg, 0) > 0);
            let header = libc::CMSG_FIRSTHDR(&raw const msg);
            assert!(!header.is_null() && (*header).cmsg_type == libc::SCM_RIGHTS);
            libc::CMSG_DATA(header).cast::<RawFd>().read_unaligned()
        };
        listener.send(&[0]).unwrap();
        let ruby = unsafe { UnixStream::from_raw_fd(fd) };
        ruby.set_nonblocking(true).unwrap();
        ruby
    }

    /// Makes a connection from A to a listener on B, and returns Ruby's
    /// end of it on each side.
    fn connected(a: &mut Stack, b: &mut Stack) -> (UnixStream, UnixStream) {
        let listener = listen(b, 7, 4);
        assert_eq!(message(&listener), Some(vec![status::OK]));
        let mut client = connect(a, B, 7);
        settle(a, b);
        assert_eq!(read(&mut client), (vec![status::OK], false));
        (client, accept(&listener))
    }

    /// Returns the byte at a place in the stream that the tests send.
    fn byte(at: usize) -> u8 {
        (at % 251) as u8
    }

    /// Writes as much more of the stream as Ruby's end takes now, up to
    /// `end`, and returns where it stopped.
    fn write_from(ruby: &mut UnixStream, mut at: usize, end: usize) -> usize {
        while at < end {
            let chunk: Vec<u8> = (at..end.min(at + 65536)).map(byte).collect();
            match ruby.write(&chunk) {
                Ok(n) => at += n,
                Err(_) => break,
            }
        }
        at
    }

    /// Says whether an IPv4 packet is a TCP reset.
    fn is_reset(packet: &[u8]) -> bool {
        packet[9] == 6 && packet[20 + 13] & 0x04 != 0
    }

    #[test]
    fn a_socket_has_the_settings_that_the_stack_gives() {
        let mut a = stack(A);
        let _ruby = connect(&mut a, B, 7);
        let s = a.sockets.get::<tcp::Socket>(a.conns[0].handle);
        assert_eq!(s.congestion_control(), tcp::CongestionControl::Cubic);
        assert!(!s.nagle_enabled());
        assert_eq!(s.min_rto(), SDuration::from_millis(200));
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
        // other end is closed, and B ends the connection.
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![], true));
        drop(ruby);
        settle(&mut a, &mut b);
        std::thread::sleep(LINGER);
        settle(&mut a, &mut b);
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
        let statuses: Vec<Vec<u8>> = rubies.iter_mut().map(|ruby| read(ruby).0).collect();
        assert_eq!(statuses, [vec![status::OK], vec![status::OK], vec![]], "the third SYN was dropped");
        // Ruby accepts one, and there is room for the third when its SYN
        // is sent again, a second after the first time.
        listener.send(&[0]).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        settle(&mut a, &mut b);
        assert_eq!(read(&mut rubies[2]), (vec![status::OK], false));
        assert_eq!(b.listeners[0].unaccepted, 2);
    }

    #[test]
    fn handshakes_that_their_peer_resets_leave_the_backlog() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 2);
        // As many SYNs as the backlog arrive in one burst.
        let rubies: Vec<UnixStream> = (0..2).map(|_| connect(&mut a, B, 7)).collect();
        a.turn();
        while let Some(packet) = a.transmit() {
            b.receive(packet);
        }
        b.turn();
        let answers = std::iter::from_fn(|| b.transmit()).filter(|packet| !is_reset(packet)).count();
        assert_eq!(answers, 2, "each SYN is answered");
        // The answers are lost. Ruby gives both attempts up, and A resets
        // them.
        drop(rubies);
        settle(&mut a, &mut b);
        // The next SYN finds room, and is not dropped.
        let mut ruby = connect(&mut a, B, 7);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
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
    fn bytes_cross_each_way_and_each_way_ends_alone() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.write_all(b"ping").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"ping".to_vec(), true));
        // The other way is still open.
        server.write_all(b"pong").unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut client), (b"pong".to_vec(), false));
        server.shutdown(Shutdown::Write).unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut client), (vec![], true));
        // The socket that owes the last ACK stays a while, and then goes.
        std::thread::sleep(LINGER);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    #[test]
    fn a_reader_that_stops_holds_the_writer_and_loses_nothing() {
        const END: usize = 4 << 20;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        let mut at = 0;
        loop {
            let before = at;
            at = write_from(&mut client, at, END);
            settle(&mut a, &mut b);
            if at == before {
                break;
            }
        }
        // Nobody reads, so the two pairs and the two sockets are full.
        assert!((2 * TCP_BUF..END).contains(&at), "the writer waits after {at} bytes");
        let mut got = Vec::new();
        for _ in 0..1000 {
            at = write_from(&mut client, at, END);
            settle(&mut a, &mut b);
            got.extend(read(&mut server).0);
            if got.len() == END {
                break;
            }
        }
        assert_eq!(got.len(), END);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    #[test]
    fn an_end_closed_with_bytes_unread_resets_the_connection() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (client, mut server) = connected(&mut a, &mut b);
        server.write_all(b"unread").unwrap();
        settle(&mut a, &mut b);
        drop(client);
        settle(&mut a, &mut b);
        // A reset reads as the end of the stream, and a write fails.
        assert_eq!(read(&mut server), (vec![], true));
        assert!(server.write(b"more").is_err());
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    #[test]
    fn an_end_closed_with_nothing_unread_delivers_what_it_wrote() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.write_all(b"last words").unwrap();
        drop(client);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"last words".to_vec(), true));
        // B has acknowledged the FIN, and has yet to end its stream.
        assert!(a.conns.len() == 1 && b.conns.len() == 1);
        drop(server);
        settle(&mut a, &mut b);
        std::thread::sleep(LINGER);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    /// Makes an orphan as old as it would be after this long.
    fn age(stack: &mut Stack, by: Duration) {
        let c = &mut stack.conns[0];
        c.app_gone = Some(c.app_gone.unwrap() - by);
        c.fin_wait = c.fin_wait.map(|since| since - by);
    }

    #[test]
    fn a_closed_end_waits_a_while_for_the_peer_to_end_its_stream() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (client, mut server) = connected(&mut a, &mut b);
        drop(client);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (vec![], true));
        age(&mut a, FIN_WAIT - Duration::from_secs(1));
        settle(&mut a, &mut b);
        assert!(a.conns.len() == 1 && b.conns.len() == 1, "the peer still has its time");
        age(&mut a, Duration::from_secs(1));
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty(), "and then it is reset");
        assert!(server.write(b"too late").is_err());
    }

    #[test]
    fn a_closed_end_is_reset_by_what_the_peer_sends_then() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (client, mut server) = connected(&mut a, &mut b);
        drop(client);
        settle(&mut a, &mut b);
        server.write_all(b"is anyone there?").unwrap();
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
    }

    #[test]
    fn a_closed_end_is_not_kept_for_a_peer_that_takes_nothing() {
        const END: usize = 700 << 10;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The server reads nothing, so its window shuts with part of this
        // still to send.
        let mut at = 0;
        while at < END {
            at = write_from(&mut client, at, END);
            settle(&mut a, &mut b);
        }
        drop(client);
        settle(&mut a, &mut b);
        age(&mut a, TCP_TIMEOUT - Duration::from_secs(1));
        settle(&mut a, &mut b);
        assert_eq!(a.conns.len(), 1, "the orphan still has its time");
        age(&mut a, Duration::from_secs(1));
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty());
        // The server can still read what reached it, and then the end.
        let mut got = 0;
        for _ in 0..100 {
            let (bytes, end) = read(&mut server);
            got += bytes.len();
            if end {
                break;
            }
            settle(&mut a, &mut b);
        }
        assert!(got > TCP_BUF && got < END && b.conns.is_empty(), "{got} bytes arrived");
    }

    #[test]
    fn the_peer_has_its_time_from_when_it_has_taken_everything() {
        const END: usize = 700 << 10;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The server reads nothing yet, so part of this is still to send
        // when Ruby closes its end.
        let mut at = 0;
        while at < END {
            at = write_from(&mut client, at, END);
            settle(&mut a, &mut b);
        }
        drop(client);
        settle(&mut a, &mut b);
        // The rest takes longer to deliver than the peer is given.
        age(&mut a, FIN_WAIT + Duration::from_secs(1));
        let mut got = 0;
        for _ in 0..200 {
            let (bytes, end) = read(&mut server);
            got += bytes.len();
            settle(&mut a, &mut b);
            if end {
                break;
            }
        }
        assert_eq!(got, END);
        assert!(a.conns.len() == 1 && b.conns.len() == 1, "the peer has its time from now");
        age(&mut a, FIN_WAIT);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
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

    #[test]
    fn a_quiet_connection_stays_open_until_its_peer_is_gone() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The timers of the two sockets are made to run 150 times as fast,
        // which gives them a timeout of two seconds.
        for stack in [&mut a, &mut b] {
            let s = stack.sockets.get_mut::<tcp::Socket>(stack.conns[0].handle);
            s.set_timeout(s.timeout().map(|timeout| timeout / 150));
            // An interval takes effect at once only when none was set.
            let interval = s.keep_alive().map(|interval| interval / 150);
            s.set_keep_alive(None);
            s.set_keep_alive(interval);
        }
        let quiet = Instant::now();
        while quiet.elapsed() < Duration::from_secs(3) {
            settle(&mut a, &mut b);
        }
        client.write_all(b"still here").unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"still here".to_vec(), false));
        // B is gone, and nothing answers what A sends.
        let gone = Instant::now();
        while gone.elapsed() < Duration::from_secs(3) {
            a.turn();
            while a.transmit().is_some() {}
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(read(&mut client), (vec![], true));
        assert!(a.conns.is_empty());
    }

    /// smoltcp clears a socket ten seconds after both sides have ended
    /// their streams. This test waits for that, so it runs only when
    /// asked for, as "rake slow" asks.
    #[test]
    #[ignore]
    fn what_ruby_has_not_read_outlasts_time_wait() {
        const END: usize = 400 << 10;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // Ruby ends its writing. The peer answers with more than the pair
        // holds, and ends too.
        client.shutdown(Shutdown::Write).unwrap();
        let mut at = 0;
        while at < END {
            at = write_from(&mut server, at, END);
            settle(&mut a, &mut b);
        }
        drop(server);
        let ended = Instant::now();
        while ended.elapsed() < Duration::from_secs(11) {
            settle(&mut a, &mut b);
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut got = Vec::new();
        loop {
            let (bytes, end) = read(&mut client);
            got.extend(bytes);
            if end {
                break;
            }
            settle(&mut a, &mut b);
        }
        assert_eq!(got.len(), END);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    #[test]
    fn a_fin_waits_for_a_peer_that_ended_first_to_take_the_data() {
        const END: usize = 700 << 10;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.shutdown(Shutdown::Write).unwrap();
        // The answer is more than the client holds unread, so its window
        // shuts with part of the answer still to send.
        let mut at = 0;
        while at < END {
            at = write_from(&mut server, at, END);
            settle(&mut a, &mut b);
        }
        drop(server);
        settle(&mut a, &mut b);
        let s = b.sockets.get::<tcp::Socket>(b.conns[0].handle);
        assert!(s.state() == tcp::State::CloseWait && s.send_queue() > 0, "{} with {}", s.state(), s.send_queue());
        let mut got = Vec::new();
        for _ in 0..100 {
            let (bytes, end) = read(&mut client);
            got.extend(bytes);
            if end {
                break;
            }
            settle(&mut a, &mut b);
        }
        assert_eq!(got.len(), END);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    /// Shuts the window that an IPv4 TCP packet advertises, and corrects
    /// the checksum as RFC 1624 has it.
    fn shut_window(packet: &mut [u8]) {
        let t = &mut packet[20..];
        let old = u16::from_be_bytes([t[14], t[15]]);
        let mut sum = u32::from(!u16::from_be_bytes([t[16], t[17]])) + u32::from(!old);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        t[14..16].copy_from_slice(&[0, 0]);
        t[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    // The test waits for smoltcp to probe a window, which takes seconds.
    // It runs when the tests that were passed over are asked for, as
    // "rake slow" asks.
    #[test]
    #[ignore]
    fn a_fin_does_not_ride_on_the_probe_of_a_shut_window() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // What B sends says that its window is shut, though B takes what
        // it is sent, as a peer may that takes the byte of a probe.
        let shuttle = |a: &mut Stack, b: &mut Stack| {
            a.turn();
            b.turn();
            while let Some(packet) = a.transmit() {
                b.receive(packet);
            }
            while let Some(mut packet) = b.transmit() {
                shut_window(&mut packet);
                a.receive(packet);
            }
        };
        server.write_all(b"x").unwrap();
        for _ in 0..10 {
            shuttle(&mut a, &mut b);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(read(&mut client).0, b"x");
        client.write_all(b"ab").unwrap();
        drop(client);
        let state = |a: &Stack| a.sockets.get::<tcp::Socket>(a.conns[0].handle).state();
        let begun = Instant::now();
        while state(&a) != tcp::State::FinWait2 {
            assert!(begun.elapsed() < Duration::from_secs(20), "the socket is in {}", state(&a));
            shuttle(&mut a, &mut b);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(read(&mut server), (b"ab".to_vec(), true));
        // Were the timer of the probe still set, smoltcp would now send an
        // ACK at every round, and a turn would send as many as it has
        // rounds.
        std::thread::sleep(Duration::from_millis(1500));
        while a.transmit().is_some() {}
        a.turn();
        assert!(std::iter::from_fn(|| a.transmit()).count() < 2);
    }

    #[test]
    fn a_stack_that_is_closing_sends_what_was_written() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.write_all(b"written, and not closed").unwrap();
        a.orphan();
        assert!(!a.finished());
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"written, and not closed".to_vec(), true));
        assert_eq!(read(&mut client), (vec![], true), "Ruby reads the end of its stream");
        assert!(a.finished() && b.conns.is_empty());
    }

    #[test]
    fn a_stack_that_is_closing_resets_what_does_not_end() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, _server) = connected(&mut a, &mut b);
        let _connecting = connect(&mut a, B, 8);
        client.write_all(b"never acknowledged").unwrap();
        a.orphan();
        // B is gone, and nothing that A sends is answered.
        while a.turn() {}
        let sent: Vec<Vec<u8>> = std::iter::from_fn(|| a.transmit()).collect();
        assert_eq!(sent.iter().filter(|packet| is_reset(packet)).count(), 1, "the attempt is given up");
        assert!(!a.finished());
        a.abort();
        a.poll();
        assert!(is_reset(&a.transmit().unwrap()));
    }

    #[test]
    fn a_stack_that_is_closing_sends_an_ack_that_it_delayed() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.shutdown(Shutdown::Write).unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (vec![], true));
        server.write_all(b"bye").unwrap();
        drop(server);
        b.turn();
        b.turn();
        // A peer such as Linux puts its FIN on its last segment of data.
        // smoltcp sends its FIN apart, so the FIN is put on B's segment
        // here, and the checksum is corrected as RFC 1624 has it.
        let mut last = b.transmit().unwrap();
        let t = &mut last[20..];
        let old = u16::from_be_bytes([t[12], t[13]]);
        t[13] |= 0x01;
        let new = u16::from_be_bytes([t[12], t[13]]);
        let mut sum = u32::from(!u16::from_be_bytes([t[16], t[17]])) + u32::from(!old) + u32::from(new);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        t[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        a.receive(last);
        while a.turn() {}
        assert!(matches!(a.conns[0].phase, Phase::Dead(_)) && a.transmit().is_none(), "the ACK is delayed");
        assert_eq!(read(&mut client), (b"bye".to_vec(), true));
        // The tunnel closes with no linger, as Engine::finish has it.
        a.orphan();
        a.abort();
        a.poll();
        let ack = a.transmit().expect("the ACK of the peer's FIN");
        assert!(!is_reset(&ack));
    }
}

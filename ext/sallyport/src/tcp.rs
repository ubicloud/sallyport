//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end, and moves bytes between it and the buffers of the TCP
//! socket. The buffers of both are bounded, so each direction has flow
//! control from end to end.

use crate::config::Config;
use crate::packet::{rst, syn, without_sack};
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
/// The stack's clock goes on by no more than this from one reading to the
/// next. The tunnel's thread reads it several times a second, so a longer
/// time is one in which the thread stood still.
const STEP: Duration = Duration::from_secs(1);
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
    /// The SYN is sent, and Ruby waits on its end for the status. The time
    /// is read from the stack's clock, as is every time that a connection
    /// keeps.
    Connecting(Duration),
    /// The socket waits for a SYN, or for the handshake that the SYN
    /// began. There is no socket pair yet.
    Listening,
    /// The connection is established, and its listener has yet to send
    /// Ruby its end of the pair.
    Accepting,
    Open,
    /// The connection is closed to Ruby and has no descriptor. Its socket
    /// stays until it has sent what it owes the peer.
    Dead(Duration),
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
    app_gone: Option<Duration>,
    /// Since when the connection has waited for nothing but the peer's
    /// FIN: Ruby has left, and the peer has acknowledged our FIN.
    fin_wait: Option<Duration>,
    /// The tail holds what the peer sent last and Ruby has yet to be
    /// given, once that is taken out of the socket's buffer.
    tail: VecDeque<u8>,
    /// The tunnel is closing, and the connection is treated as if Ruby
    /// had closed its end.
    orphan: bool,
    /// Ruby has shut down its reading, and may still write. The pair
    /// takes no more bytes for Ruby, so what the peer sends is dropped.
    deaf: bool,
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
            deaf: false,
        }
    }

    /// Returns our end of the pair as a system call takes it, or -1 if
    /// there is none.
    fn raw(&self) -> RawFd {
        self.fd.as_ref().map_or(-1, |fd| fd.as_raw_fd())
    }
}

// The model "conn" is of one connection from the time that it is open: how
// carry moves bytes between Ruby's descriptor and smoltcp's socket, what
// poll is asked about the descriptor, and how the connection ends. It
// leaves out a Ruby that shuts down its reading. The lines of the model
// are beside the code that they describe, and `rake tla` checks them.
//
// TLA-conn@0> EXTENDS Naturals
// TLA-conn@0> CONSTANTS Budget,   \* how many bytes each side may write
// TLA-conn@0>           TxCap,    \* how many bytes the socket holds to send
// TLA-conn@0>           RxCap,    \* how many bytes the socket holds for Ruby
// TLA-conn@0>           PairCap,  \* how many bytes the pair holds each way
// TLA-conn@0>           Linger,   \* how many ticks a dead connection keeps its socket
// TLA-conn@0>           Fault     \* the fault that a variant puts in, or "none"
// TLA-conn@0> \* The state is one record, so that a step says what it changes and no more.
// TLA-conn@0> VARIABLE s
// TLA-conn@0> Init == s = [
// TLA-conn@0>   ruby    |-> "open",   \* Ruby's end of the pair is "open", "shutwr" or "closed"
// TLA-conn@0>   r2u     |-> 0,        \* the bytes that Ruby wrote and carry has not read
// TLA-conn@0>   u2r     |-> 0,        \* the bytes that carry wrote and Ruby has not read
// TLA-conn@0>   rerr    |-> FALSE,    \* Ruby closed with bytes unread, and a read of the pair will fail
// TLA-conn@0>   wleft   |-> Budget,   \* the bytes that Ruby may still write
// TLA-conn@0>   st      |-> "Established",  \* the state that the socket is in
// TLA-conn@0>   tx      |-> 0,        \* the bytes that the socket holds and the peer has not acknowledged
// TLA-conn@0>   rx      |-> 0,        \* the bytes that the socket holds for Ruby
// TLA-conn@0>   owed    |-> "none",   \* what the socket has yet to send: "none", "ack" or "rst"
// TLA-conn@0>   peer    |-> "up",     \* "up", "fin" (it has sent its FIN) or "gone" (it is silent for good)
// TLA-conn@0>   pleft   |-> Budget,   \* the bytes that the peer may still send
// TLA-conn@0>   stuck   |-> FALSE,    \* the peer holds its window shut: it answers, and takes no data
// TLA-conn@0>   finRcvd |-> FALSE,    \* the peer's FIN has arrived
// TLA-conn@0>   fdEof   |-> FALSE,    \* Conn.fd_eof
// TLA-conn@0>   rxShut  |-> FALSE,    \* Conn.rx_shut
// TLA-conn@0>   tail    |-> 0,        \* how many bytes Conn.tail holds
// TLA-conn@0>   orphan  |-> FALSE,    \* Conn.orphan
// TLA-conn@0>   gone    |-> "no",     \* Conn.app_gone: "no", "yes" or "timeout" (TCP_TIMEOUT ago)
// TLA-conn@0>   wait    |-> "no",     \* Conn.fin_wait: "no", "yes" or "over" (FIN_WAIT ago)
// TLA-conn@0>   phase   |-> "open",   \* "open", "dead" (Phase::Dead) or "removed"
// TLA-conn@0>   age     |-> 0,        \* the ticks since the connection died
// TLA-conn@0>   kick    |-> FALSE,    \* the loop will turn without a wait for the descriptor
// TLA-conn@0>   moved   |-> FALSE,    \* what a pass of carry returns: whether it moved,
// TLA-conn@0>   fate    |-> "keep"]   \* and what becomes of the connection
// TLA-conn@0>
// TLA-conn@0> Min(a, b) == IF a < b THEN a ELSE b
// TLA-conn@0> \* These are may_send and may_recv of smoltcp's socket. may_recv is also
// TLA-conn@0> \* true while the socket holds bytes for Ruby, which the model writes as
// TLA-conn@0> \* rx > 0.
// TLA-conn@0> MaySend(t) == t.st \in {"Established", "CloseWait"}
// TLA-conn@0> MayRecv(t) == t.st \in {"Established", "FinWait1", "FinWait2"}
// TLA-conn@0> \* sys::hung_up. poll reports a hangup on our end when Ruby has closed its
// TLA-conn@0> \* end, and when each end has shut down its writing. carry shuts ours down
// TLA-conn@0> \* to pass on the peer's FIN, and orphan shuts it down when the tunnel
// TLA-conn@0> \* closes.
// TLA-conn@0> HungUp(t) == t.ruby = "closed" \/ (t.ruby = "shutwr" /\ (t.rxShut \/ t.orphan))
//
// The model takes this much of Ruby, of the peer and of smoltcp.
//
// TLA-conn@10> \* Ruby may write, read, shut down its writing and close, in any order
// TLA-conn@10> \* and at any time. The model takes it that Ruby writes nothing to a
// TLA-conn@10> \* tunnel that it has closed. Nothing in the kernel holds Ruby to that:
// TLA-conn@10> \* the pair would take such bytes, and nothing would send them.
// TLA-conn@10> RubyWrite == /\ s.ruby = "open" /\ s.phase = "open" /\ ~s.orphan /\ s.wleft > 0 /\ s.r2u < PairCap
// TLA-conn@10>              /\ s' = [s EXCEPT !.r2u = @ + 1, !.wleft = @ - 1]
// TLA-conn@10> RubyRead == /\ s.ruby # "closed" /\ s.u2r > 0 /\ s' = [s EXCEPT !.u2r = @ - 1]
// TLA-conn@10> RubyShutWr == /\ s.ruby = "open" /\ s' = [s EXCEPT !.ruby = "shutwr"]
// TLA-conn@10> \* What Ruby wrote stays for carry to read. What carry wrote and Ruby did
// TLA-conn@10> \* not read is lost, and the kernel says so once, as an error.
// TLA-conn@10> RubyClose == /\ s.ruby # "closed"
// TLA-conn@10>              /\ s' = [s EXCEPT !.ruby = "closed", !.rerr = s.u2r > 0 /\ s.phase = "open", !.u2r = 0]
// TLA-conn@10> Ruby == RubyWrite \/ RubyRead \/ RubyShutWr \/ RubyClose
// TLA-conn@10>
// TLA-conn@10> \* The peer may send, acknowledge, end its stream, reset the connection,
// TLA-conn@10> \* go silent and hold its window shut. A packet from it wakes the loop.
// TLA-conn@10> PeerData == /\ s.peer = "up" /\ s.pleft > 0 /\ MayRecv(s) /\ s.rx < RxCap
// TLA-conn@10>             /\ s' = [s EXCEPT !.rx = @ + 1, !.pleft = @ - 1, !.kick = TRUE]
// TLA-conn@10> PeerAck == /\ s.peer # "gone" /\ ~s.stuck /\ s.tx > 0 /\ s.st # "Closed"
// TLA-conn@10>            /\ s' = [s EXCEPT !.tx = @ - 1, !.kick = TRUE]
// TLA-conn@10> \* Our FIN follows our data, so it is acknowledged after the data.
// TLA-conn@10> PeerAckFin == /\ s.peer # "gone" /\ s.tx = 0 /\ s.st \in {"FinWait1", "Closing", "LastAck"}
// TLA-conn@10>               /\ s' = CASE s.st = "FinWait1" -> [s EXCEPT !.st = "FinWait2", !.kick = TRUE]
// TLA-conn@10>                         [] s.st = "Closing" -> [s EXCEPT !.st = "TimeWait", !.kick = TRUE]
// TLA-conn@10>                         [] s.st = "LastAck" -> [s EXCEPT !.st = "Closed", !.owed = "none", !.kick = TRUE]
// TLA-conn@10> \* The model takes it that the socket takes the peer's FIN only when it
// TLA-conn@10> \* has taken all that the peer sent before it.
// TLA-conn@10> PeerFin == /\ s.peer = "up"
// TLA-conn@10>            /\ s' = CASE s.st = "Established" -> [s EXCEPT !.st = "CloseWait", !.owed = "ack", !.finRcvd = TRUE,
// TLA-conn@10>                                                           !.peer = "fin", !.kick = TRUE]
// TLA-conn@10>                      [] s.st = "FinWait1" -> [s EXCEPT !.st = "Closing", !.owed = "ack", !.finRcvd = TRUE,
// TLA-conn@10>                                                        !.peer = "fin", !.kick = TRUE]
// TLA-conn@10>                      [] s.st = "FinWait2" -> [s EXCEPT !.st = "TimeWait", !.owed = "ack", !.finRcvd = TRUE,
// TLA-conn@10>                                                        !.peer = "fin", !.kick = TRUE]
// TLA-conn@10>                      [] OTHER -> [s EXCEPT !.peer = "fin", !.kick = TRUE]
// TLA-conn@10> \* A reset leaves what was received for Ruby to read, and leaves nothing
// TLA-conn@10> \* to send.
// TLA-conn@10> PeerRst == /\ s.peer # "gone" /\ s.st # "Closed"
// TLA-conn@10>            /\ s' = [s EXCEPT !.peer = "gone", !.st = "Closed", !.owed = "none", !.tx = 0, !.kick = TRUE]
// TLA-conn@10> PeerGone == /\ s.peer # "gone" /\ s' = [s EXCEPT !.peer = "gone"]
// TLA-conn@10> PeerStuck == /\ s.peer # "gone" /\ ~s.stuck /\ s' = [s EXCEPT !.stuck = TRUE]
// TLA-conn@10> Peer == PeerData \/ PeerAck \/ PeerAckFin \/ PeerFin \/ PeerRst \/ PeerGone \/ PeerStuck
// TLA-conn@10>
// TLA-conn@10> \* smoltcp closes a socket that has taken nothing from its peer for
// TLA-conn@10> \* TCP_TIMEOUT, and resets the peer. It counts the silence whether or not
// TLA-conn@10> \* anything waits for an answer. So the socket asks a quiet peer to
// TLA-conn@10> \* answer, with set_keep_alive, and the model takes it that the socket
// TLA-conn@10> \* hears a peer that is there. The stack's clock does not count the time
// TLA-conn@10> \* that the thread stood still, so the socket has asked by then.
// TLA-conn@10> TcpTimeout == /\ s.st \notin {"Closed", "TimeWait"} /\ s.phase # "removed"
// TLA-conn@10>               /\ (s.peer = "gone" \/ Fault = "no keep-alive")
// TLA-conn@10>               /\ s' = [s EXCEPT !.st = "Closed", !.owed = "rst", !.tx = 0, !.kick = TRUE]
// TLA-conn@10> \* smoltcp clears a socket that has been in TIME-WAIT for ten seconds, and
// TLA-conn@10> \* the bytes that it holds for Ruby with it. The loop has turned many
// TLA-conn@10> \* times by then.
// TLA-conn@10> TimeWaitOver == /\ s.st = "TimeWait" /\ s.phase = "open" /\ s.owed = "none" /\ ~s.kick
// TLA-conn@10>                 /\ s' = [s EXCEPT !.st = "Closed", !.rx = 0, !.kick = TRUE]
// TLA-conn@10> \* Time passes for a connection that Ruby has left. The code has no timer
// TLA-conn@10> \* for that, and nothing wakes the loop: the tick turns it, and carry
// TLA-conn@10> \* looks at the clock.
// TLA-conn@10> Leaves == /\ s.phase = "open"
// TLA-conn@10>           /\ \/ s.gone = "yes" /\ s' = [s EXCEPT !.gone = "timeout"]
// TLA-conn@10>              \/ s.wait = "yes" /\ s' = [s EXCEPT !.wait = "over"]
// TLA-conn@10> \* A tick passes for a dead connection. smoltcp delays an ACK for 10 ms at
// TLA-conn@10> \* most and a tick is longer, so no tick passes while the socket owes
// TLA-conn@10> \* something.
// TLA-conn@10> Tick == /\ s.phase = "dead" /\ s.owed = "none" /\ s.age < Linger /\ s' = [s EXCEPT !.age = @ + 1]

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
    /// The stack's time, and when it was last read.
    clock: Duration,
    read_at: Instant,
    /// Selective acknowledgement is left on offer in the SYNs.
    sack: bool,
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
    pub fn new(cfg: &Config, sack: bool) -> Stack {
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
            clock: Duration::ZERO,
            read_at: Instant::now(),
            sack,
        }
    }

    fn now(&mut self) -> SInstant {
        self.time_at(Instant::now())
    }

    /// Returns the stack's time at a moment of the system's clock. Ctrl-Z
    /// stops a process, and the tunnel's thread with it, for minutes at a
    /// time. The stack's clock does not count those minutes. smoltcp would
    /// count them as silence, and would take every peer that was quiet to
    /// be gone.
    fn time_at(&mut self, real: Instant) -> SInstant {
        self.clock += real.saturating_duration_since(self.read_at).min(STEP);
        self.read_at = real;
        SInstant::from_micros(self.clock.as_micros() as i64)
    }

    /// Queues an IP packet that arrived for the stack.
    pub fn receive(&mut self, mut packet: Vec<u8>) {
        if !self.sack {
            without_sack(&mut packet);
        }
        self.link.rx.push_back(packet);
    }

    /// Returns the next IP packet that the stack wants sent.
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        let mut packet = self.link.tx.pop_front()?;
        if !self.sack {
            without_sack(&mut packet);
        }
        Some(packet)
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
        let phase = Phase::Connecting(self.clock);
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

    // TLA-conn> \* Every turn of the loop has each socket send what it owes.
    // TLA-conn> Dispatch == /\ s.owed # "none" /\ s.phase # "removed" /\ s' = [s EXCEPT !.owed = "none"]
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

    // TLA-conn> \* The tunnel is closing. orphan shuts down our end of the pair, and the
    // TLA-conn> \* loop turns at once.
    // TLA-conn> Orphan == /\ ~s.orphan /\ s.phase # "removed"
    // TLA-conn>           /\ s' = [s EXCEPT !.orphan = TRUE, !.kick = TRUE,
    // TLA-conn>                             !.gone = IF s.phase = "open" /\ @ = "no" THEN "yes" ELSE @]
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
                c.app_gone = c.app_gone.or(Some(self.clock));
            }
        }
    }

    /// Says whether every connection has ended, and has had the time to
    /// send its last ACK.
    pub fn finished(&self) -> bool {
        self.conns.iter().all(|c| matches!(c.phase, Phase::Dead(since) if self.clock - since >= LAST_ACK))
    }

    // TLA-conn> \* The linger is over. abort resets a connection that has not ended. The
    // TLA-conn> \* poll that follows sends what every socket owes, an ACK that was
    // TLA-conn> \* delayed among it, and the thread ends.
    // TLA-conn> Finish == /\ s.orphan /\ s.phase # "removed"
    // TLA-conn>           /\ s' = [s EXCEPT !.phase = "removed", !.st = "Closed", !.owed = "none"]
    /// Resets every connection that has not ended. The resets leave at
    /// the next poll.
    pub fn abort(&mut self) {
        for c in self.conns.iter().filter(|c| !matches!(c.phase, Phase::Dead(_))) {
            self.sockets.get_mut::<tcp::Socket>(c.handle).abort();
        }
        // A socket that has just taken the peer's FIN may still delay its
        // ACK, and the next poll is the last. So the stack's clock is put
        // on by the delay, and the ACK leaves with the resets.
        self.clock += ACK_DELAY;
    }

    /// Returns how long the stack can wait before its next timer.
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let now = self.now();
        self.iface.poll_delay(now, &self.sockets).map(|d| Duration::from_micros(d.total_micros()))
    }

    // TLA-conn@70> \* pump acts on what a pass of carry decided. A connection that is closed
    // TLA-conn@70> \* or reset keeps its socket, as Phase::Dead, until the socket has sent
    // TLA-conn@70> \* what it owes. If the pass moved anything, the loop turns again at once.
    // TLA-conn@70> PumpOpen(woken) ==
    // TLA-conn@70>   /\ s.phase = "open" /\ woken
    // TLA-conn@70>   /\ \E p \in {Pass(s)} :
    // TLA-conn@70>      s' = IF p.fate = "keep" THEN [p EXCEPT !.kick = p.moved, !.moved = FALSE]
    // TLA-conn@70>           ELSE [p EXCEPT !.st = IF p.fate = "abort" THEN "Closed" ELSE @,
    // TLA-conn@70>                          !.owed = IF p.fate = "abort" /\ p.st # "Closed" THEN "rst" ELSE @,
    // TLA-conn@70>                          !.tx = IF p.fate = "abort" THEN 0 ELSE @,
    // TLA-conn@70>                          !.phase = IF Fault = "remove at once" THEN "removed" ELSE "dead",
    // TLA-conn@70>                          !.age = 0, !.kick = FALSE, !.moved = FALSE, !.fate = "keep"]
    /// Moves every connection as far as it will go.
    fn pump(&mut self) -> bool {
        let mut moved = false;
        let mut i = 0;
        while i < self.conns.len() {
            let c = &mut self.conns[i];
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            let (m, fate) = step(c, s, &mut self.listeners, self.clock);
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
                    c.phase = Phase::Dead(self.clock);
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

    // TLA-conn> \* poll_fds. The pair is read while the socket has room, and written
    // TLA-conn> \* while there are bytes for Ruby. A descriptor with neither asked of it
    // TLA-conn> \* is watched for a hangup, until the hangup has been seen.
    // TLA-conn> Reads(t) == ~t.fdEof /\ MaySend(t) /\ t.tx < TxCap
    // TLA-conn> Writes(t) == t.rx > 0 \/ t.tail > 0
    // TLA-conn> Watched(t) == \/ Reads(t) \/ Writes(t)
    // TLA-conn>               \/ t.gone = "no" /\ Fault # "hangup unwatched"
    // TLA-conn>               \/ Fault = "hangup always watched"
    // TLA-conn> \* FdReady says whether poll returns for the descriptor. It reports a
    // TLA-conn> \* hangup whatever it is asked. It reports room in the pair later than a
    // TLA-conn> \* write would find it: only when Ruby has no more than a quarter of the
    // TLA-conn> \* pair left to read.
    // TLA-conn> FdReady(t) == /\ t.phase = "open" /\ Watched(t)
    // TLA-conn>               /\ \/ Reads(t) /\ (t.r2u > 0 \/ t.ruby # "open")
    // TLA-conn>                  \/ Writes(t) /\ (4 * t.u2r <= PairCap \/ t.ruby = "closed")
    // TLA-conn>                  \/ HungUp(t)
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

// TLA-conn> \* step removes a dead connection when its socket has sent what it owed,
// TLA-conn> \* or when the peer's FIN has had long enough to be acknowledged.
// TLA-conn> PumpDead == /\ s.phase = "dead"
// TLA-conn>             /\ (s.st = "Closed" /\ s.owed = "none") \/ s.age >= Linger
// TLA-conn>             /\ s' = [s EXCEPT !.phase = "removed"]
/// Moves one connection as far as it will go. Returns whether it moved,
/// and what becomes of it.
fn step(c: &mut Conn, s: &mut tcp::Socket, listeners: &mut [Listener], now: Duration) -> (bool, Fate) {
    match c.phase {
        Phase::Dead(since) => {
            let sent = match s.state() {
                // smoltcp forgets the peer once it has no more to send it.
                tcp::State::Closed => s.remote_endpoint().is_none(),
                // The peer's FIN is owed an ACK.
                _ => now - since >= LINGER,
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
                let late = now - since + Duration::from_secs(1) >= TCP_TIMEOUT;
                sys::send(c.raw(), &[if late { status::TIMED_OUT } else { status::REFUSED }]);
                (true, Fate::Close)
            }
            _ => {
                sys::send(c.raw(), &[status::OK]);
                c.phase = Phase::Open;
                (true, Fate::Keep)
            }
        },
        Phase::Open => carry(c, s, now),
    }
}

/// Moves bytes each way for an open connection, and passes on the end of
/// each direction.
fn carry(c: &mut Conn, s: &mut tcp::Socket, now: Duration) -> (bool, Fate) {
    let mut moved = false;
    let was_deaf = c.deaf;

    // A pass of carry is the steps of the model that follow, each from the
    // state that the step before it left.
    //
    // TLA-conn> \* The pair is read into the socket while the socket has room. If the
    // TLA-conn> \* loop reads once more than there are bytes, that read says why there
    // TLA-conn> \* are none: an error, the end of what Ruby will write, or nothing yet.
    // TLA-conn> \* An orphan's pair is read until it is empty, and no more.
    // TLA-conn> Read(t) == LET eof == t.fdEof \/ ~MaySend(t)
    // TLA-conn>                n == IF eof THEN 0 ELSE Min(t.r2u, TxCap - t.tx)
    // TLA-conn>                more == ~eof /\ t.tx + n < TxCap
    // TLA-conn>                end == more /\ ~t.rerr /\ (t.ruby # "open" \/ t.orphan)
    // TLA-conn>            IN [t EXCEPT !.fdEof = eof \/ end, !.tx = @ + n, !.r2u = @ - n,
    // TLA-conn>                         !.moved = n > 0 \/ end, !.fate = IF more /\ t.rerr THEN "abort" ELSE "keep"]
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
    // TLA-conn> Fin(t) == IF MaySend(t) /\ t.fdEof /\ (t.tx = 0 \/ Fault = "early fin")
    // TLA-conn>           THEN [t EXCEPT !.st = IF @ = "Established" THEN "FinWait1" ELSE "LastAck", !.moved = TRUE]
    // TLA-conn>           ELSE t
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
    // TLA-conn> Hung(t) == IF t.gone = "no" /\ HungUp(t) THEN [t EXCEPT !.gone = "yes"] ELSE t
    if c.app_gone.is_none() && sys::hung_up(fd) {
        c.app_gone = Some(now);
    }
    // TLA-conn> Waits(t) == IF t.wait = "no" /\ t.gone # "no" /\ t.st = "FinWait2" THEN [t EXCEPT !.wait = "yes"] ELSE t
    // The peer's time to end its stream begins when Ruby has left and the
    // peer has acknowledged our FIN, whichever comes later.
    if c.fin_wait.is_none() && c.app_gone.is_some() && s.state() == tcp::State::FinWait2 {
        c.fin_wait = Some(now);
    }

    // TLA-conn> Tail(t) == IF t.st = "TimeWait" /\ Fault # "no tail"
    // TLA-conn>            THEN [t EXCEPT !.tail = @ + t.rx, !.rx = 0] ELSE t
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
    // TLA-conn> \* Ruby is given the tail and then what the socket holds, for as much as
    // TLA-conn> \* the pair has room. The write fails if Ruby has closed its end, or if
    // TLA-conn> \* orphan has shut ours down.
    // TLA-conn> Give(t) == LET n == Min(t.tail + t.rx, PairCap - t.u2r)
    // TLA-conn>                k == Min(n, t.tail)
    // TLA-conn>            IN IF t.tail + t.rx = 0 THEN t
    // TLA-conn>               ELSE IF t.ruby = "closed" \/ t.orphan THEN [t EXCEPT !.fate = "abort"]
    // TLA-conn>               ELSE [t EXCEPT !.tail = @ - k, !.rx = @ - (n - k), !.u2r = @ + n, !.moved = @ \/ n > 0]
    // A write to the pair fails when Ruby has closed its end, and also
    // when Ruby has only shut down its reading. poll reports a hangup for
    // the first and none for the second.
    let deafened = |n: isize, c: &Conn| n == sys::PIPE && !c.orphan && !sys::hung_up(fd);
    while !c.deaf && !c.tail.is_empty() {
        match sys::send(fd, c.tail.as_slices().0) {
            n if n > 0 => {
                c.tail.drain(..n as usize);
                moved = true;
            }
            sys::AGAIN => break,
            n if deafened(n, c) => c.deaf = true,
            _ => return (true, Fate::Abort),
        }
    }
    while !c.deaf && s.can_recv() {
        match s.recv(|buf| {
            let n = sys::send(fd, buf);
            (n.max(0) as usize, n)
        }) {
            Ok(n) if n > 0 => moved = true,
            Ok(sys::AGAIN) => break,
            Ok(n) if deafened(n, c) => c.deaf = true,
            // Ruby closed its end with bytes still to come.
            _ => return (true, Fate::Abort),
        }
    }
    if c.deaf && !was_deaf {
        // The pair has just refused a write, and poll reports no hangup.
        // Ruby has shut down its reading, or its close of its end is under
        // way, which looks the same for a moment. The bytes stay, and the
        // next pass tells which it was.
        moved = true;
    } else if c.deaf && c.app_gone.is_some() && (s.can_recv() || !c.tail.is_empty()) {
        // A hangup has shown since, so Ruby has left. What the peer sends
        // is reset, as it is for any end that is closed.
        return (true, Fate::Abort);
    } else if c.deaf {
        c.tail.clear();
        while s.can_recv() {
            let _ = s.recv(|buf| (buf.len(), ()));
            moved = true;
        }
    }
    // TLA-conn> End(t) == IF ~MayRecv(t) /\ t.rx = 0 /\ t.tail = 0 /\ (~t.rxShut \/ Fault = "restless")
    // TLA-conn>           THEN [t EXCEPT !.rxShut = TRUE, !.moved = TRUE] ELSE t
    if !c.rx_shut && !s.may_recv() && !s.can_recv() && c.tail.is_empty() {
        // The peer will send no more, and Ruby has been given all of it.
        sys::shutdown_write(fd);
        c.rx_shut = true;
        moved = true;
    }

    // TLA-conn> Fated(t) == [t EXCEPT !.fate =
    // TLA-conn>     IF t.st \in {"Closed", "TimeWait"} /\ t.fdEof /\ (t.rxShut \/ Fault = "early close") THEN "close"
    // TLA-conn>     ELSE IF t.st = "FinWait2" /\ (t.orphan \/ t.wait = "over") THEN "abort"
    // TLA-conn>     ELSE IF t.gone = "timeout" /\ Fault # "no deadline" THEN "abort"
    // TLA-conn>     ELSE "keep"]
    // An orphan is a connection that nobody is left to use on Ruby's side.
    let orphaned = c.app_gone.map(|since| now - since);
    let waited = c.fin_wait.map(|since| now - since);
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

// TLA-conn@60> \* carry returns from a step that reset the connection, and makes no
// TLA-conn@60> \* later step. The set of one element has TLC work out t once, where it
// TLA-conn@60> \* would otherwise work it out again for each place that names it.
// TLA-conn@60> Then(t, Step(_)) == CHOOSE r \in {IF v.fate = "abort" THEN v ELSE Step(v) : v \in {t}} : TRUE
// TLA-conn@60> Pass(t) == Then(Then(Then(Then(Then(Then(Then(Read(t), Fin), Hung), Waits), Tail), Give), End), Fated)
//
// TLA-conn@90> Loop == PumpOpen(s.kick \/ FdReady(s)) \/ PumpDead \/ Dispatch \/ Tick
// TLA-conn@90> \* The tick turns the loop four times a second, whatever else happens.
// TLA-conn@90> TickPump == PumpOpen(TRUE)
// TLA-conn@90> Timers == TcpTimeout \/ TimeWaitOver \/ Leaves \/ Finish
// TLA-conn@90> Next == Ruby \/ Peer \/ Orphan \/ Timers \/ Loop \/ TickPump
// TLA-conn@90> \* The loop and the timers run when they can. Ruby and the peer owe
// TLA-conn@90> \* nothing: each may stop at any point and never move again.
// TLA-conn@90> Spec == Init /\ [][Next]_s /\ WF_s(Loop) /\ WF_s(TickPump) /\ WF_s(Timers)
// TLA-conn@90>
// TLA-conn@90> \* A socket is not removed while it owes the peer a reset or an ACK.
// TLA-conn@90> RemovedClean == s.phase = "removed" => s.owed = "none"
// TLA-conn@90> \* A dead connection's socket is closed, or waits out its TIME-WAIT.
// TLA-conn@90> DeadEnds == s.phase = "dead" => s.st \in {"Closed", "TimeWait"}
// TLA-conn@90> \* carry passes on the end of the peer's stream only when Ruby has been
// TLA-conn@90> \* given all that the peer sent. A tunnel that closes ends what Ruby
// TLA-conn@90> \* reads at once, with orphan, whatever the socket holds.
// TLA-conn@90> NoneWithheld == s.rxShut => s.rx = 0 /\ s.tail = 0
// TLA-conn@90> \* Our FIN is sent only when carry has taken all that Ruby wrote.
// TLA-conn@90> FinIsLast == s.phase = "open" /\ s.st \in {"FinWait1", "FinWait2", "Closing", "LastAck", "TimeWait"}
// TLA-conn@90>                => s.fdEof /\ s.r2u = 0
// TLA-conn@90> \* The socket has nothing left to send when its FIN is queued. smoltcp
// TLA-conn@90> \* does not send a FIN well behind data that a shut window holds back.
// TLA-conn@90> FinIsBare == s.st \in {"FinWait1", "Closing", "LastAck"} => s.tx = 0
// TLA-conn@90> \* The tail is older than what the socket holds, and Ruby is given the
// TLA-conn@90> \* tail first. The socket holds nothing for Ruby while the tail has bytes.
// TLA-conn@90> TailIsFirst == s.tail > 0 => s.rx = 0
// TLA-conn@90> \* When poll would wait, a pass of carry would change nothing. So nothing
// TLA-conn@90> \* that poll can report waits for the tick. Two things do wait for it, or
// TLA-conn@90> \* for the next packet. One is room in the pair that poll does not report
// TLA-conn@90> \* yet. The other is a deadline of a connection that Ruby has left.
// TLA-conn@90> NoMissedWake == s.phase = "open" /\ ~s.kick /\ ~FdReady(s)
// TLA-conn@90>                   => \/ Pass(s) = s
// TLA-conn@90>                      \/ 4 * s.u2r > PairCap
// TLA-conn@90>                      \/ Pass(s).fate = "abort" /\ (s.gone = "timeout" \/ s.wait = "over")
// TLA-conn@90> \* When poll returns for the descriptor, a pass of carry changes
// TLA-conn@90> \* something. So the loop does not spin on the descriptor.
// TLA-conn@90> NoSpin == s.phase = "open" /\ FdReady(s) => Pass(s) # s
// TLA-conn@90> \* A pass that follows another at once moves nothing. So the loop does
// TLA-conn@90> \* not spin on what carry returns either.
// TLA-conn@90> Settles == s.phase = "open" =>
// TLA-conn@90>              \A p \in {Pass(s)} : p.fate = "keep" => ~Pass([p EXCEPT !.moved = FALSE]).moved
// TLA-conn@90> \* A state that the loop has seen owes none of these: the end of the
// TLA-conn@90> \* peer's stream to Ruby, our FIN to the peer, the close, and the read
// TLA-conn@90> \* that finds the end of what Ruby wrote to a tunnel that is closing.
// TLA-conn@90> EndPassedOn == s.phase = "open" /\ ~s.kick /\ ~MayRecv(s) /\ s.rx = 0 /\ s.tail = 0 => s.rxShut
// TLA-conn@90> FinQueued == s.phase = "open" /\ ~s.kick /\ s.fdEof /\ MaySend(s) => s.tx > 0
// TLA-conn@90> ClosedWhenDone == s.phase = "open" /\ ~s.kick => ~(s.st \in {"Closed", "TimeWait"} /\ s.fdEof /\ s.rxShut)
// TLA-conn@90> OrphanRead == s.phase = "open" /\ ~s.kick /\ s.orphan /\ MaySend(s) /\ s.tx < TxCap => s.fdEof
// TLA-conn@90> \* Bytes are neither lost nor doubled on their way. What leaves the pair
// TLA-conn@90> \* goes into the socket, and what Ruby is given leaves the socket or the
// TLA-conn@90> \* tail.
// TLA-conn@90> FromRuby == [][s'.phase = "open" /\ s'.r2u < s.r2u => s'.r2u + s'.tx = s.r2u + s.tx]_s
// TLA-conn@90> ToRuby == [][s'.u2r > s.u2r => s'.u2r + s'.rx + s'.tail = s.u2r + s.rx + s.tail]_s
// TLA-conn@90> \* While the connection is open and Ruby has not closed its end, what the
// TLA-conn@90> \* peer sent leaves the socket and the tail only into Ruby's hands.
// TLA-conn@90> NoneDropped == [][s'.phase = "open" /\ s.ruby # "closed" /\ s'.rx + s'.tail < s.rx + s.tail
// TLA-conn@90>                     => s'.u2r + s'.rx + s'.tail = s.u2r + s.rx + s.tail]_s
// TLA-conn@90> \* And a connection does not end with bytes for a Ruby that is there.
// TLA-conn@90> NoneDroppedAtEnd == [][s.phase = "open" /\ s'.phase # "open" /\ s.ruby # "closed" /\ ~s.orphan
// TLA-conn@90>                          => s'.rx + s'.tail = 0]_s
// TLA-conn@90> \* The stack ends a connection only if Ruby is gone, the peer is gone, or
// TLA-conn@90> \* each has ended its stream.
// TLA-conn@90> EndsForCause == [][s.phase = "open" /\ s'.phase # "open"
// TLA-conn@90>                      => \/ s.ruby = "closed" \/ s.orphan \/ s.peer = "gone"
// TLA-conn@90>                         \/ s.ruby = "shutwr" /\ s.finRcvd]_s
// TLA-conn@90> \* A dead connection's socket goes, whether or not Ruby ever closes its end.
// TLA-conn@90> DeadGoes == s.phase = "dead" ~> s.phase = "removed"
// TLA-conn@90> \* If a peer is silent for good, its socket is closed, or goes.
// TLA-conn@90> SilenceEnds == s.peer = "gone" ~> s.st = "Closed" \/ s.phase = "removed"
// TLA-conn@90> \* Once Ruby has closed its end, the connection is let go, whatever the
// TLA-conn@90> \* peer does or fails to do.
// TLA-conn@90> LetGo == s.ruby = "closed" ~> s.phase = "removed"
// TLA-conn@90> \* CleanEof says that Ruby reads the end of the stream only when the peer
// TLA-conn@90> \* ended it. It does not hold: a reset ends the stream too. Ruby then
// TLA-conn@90> \* reads the end, or ECONNRESET if the pair still held bytes that it had
// TLA-conn@90> \* written.
// TLA-conn@90> CleanEof == s.ruby # "closed" /\ s.rxShut => s.finRcvd
//
// The buffers of the model hold a byte each, so each is either empty or
// full.
//
// TLA-conn.cfg> SPECIFICATION Spec
// TLA-conn.cfg> CONSTANTS Budget = 2
// TLA-conn.cfg>   TxCap = 1
// TLA-conn.cfg>   RxCap = 1
// TLA-conn.cfg>   PairCap = 1
// TLA-conn.cfg>   Linger = 2
// TLA-conn.cfg>   Fault = "none"
// TLA-conn.cfg> INVARIANTS RemovedClean DeadEnds NoneWithheld FinIsLast FinIsBare TailIsFirst
// TLA-conn.cfg>   NoMissedWake NoSpin Settles EndPassedOn FinQueued ClosedWhenDone OrphanRead
// TLA-conn.cfg> PROPERTIES NoneDropped NoneDroppedAtEnd FromRuby ToRuby EndsForCause DeadGoes SilenceEnds LetGo
// TLA-conn.cfg> CHECK_DEADLOCK FALSE
//
// With room for two bytes, a buffer can also be part full.
//
// TLA-conn.cfg/roomy> Budget = 3
// TLA-conn.cfg/roomy> TxCap = 2
// TLA-conn.cfg/roomy> RxCap = 2
// TLA-conn.cfg/roomy> PairCap = 2
//
// Each of these variants has a fault that the code avoids, and the model
// finds each. A socket is removed as soon as Ruby's part is over:
//
// TLA-conn.cfg/remove-at-once!RemovedClean> Fault = "remove at once"
//
// poll is not asked about a descriptor that is neither read nor written:
//
// TLA-conn.cfg/hangup-unwatched!NoMissedWake> Fault = "hangup unwatched"
//
// poll is asked about a hangup that it has already reported:
//
// TLA-conn.cfg/hangup-always-watched!NoSpin> Fault = "hangup always watched"
//
// carry says at every pass that it moved, once the peer has ended its
// stream:
//
// TLA-conn.cfg/restless!Settles> Fault = "restless"
//
// A connection that Ruby has left has no deadline but the one in
// FIN-WAIT-2:
//
// TLA-conn.cfg/no-deadline!LetGo> Fault = "no deadline"
//
// The socket does not ask a quiet peer to answer:
//
// TLA-conn.cfg/no-keep-alive!EndsForCause> Fault = "no keep-alive"
//
// What Ruby has yet to be given stays in the socket through TIME-WAIT:
//
// TLA-conn.cfg/no-tail!NoneDropped> Fault = "no tail"
//
// A connection is closed when both streams have ended, though Ruby has
// yet to be given the last bytes that the peer sent:
//
// TLA-conn.cfg/early-close!NoneDroppedAtEnd> Fault = "early close"
//
// Our FIN is queued behind data that the peer has yet to take. The
// socket must hold more than a byte for that:
//
// TLA-conn.cfg/early-fin!FinIsBare> Fault = "early fin"
// TLA-conn.cfg/early-fin!FinIsBare> TxCap = 2
//
// The last variant has no fault. It shows a limit of the design, which
// the comment at CleanEof describes.
//
// TLA-conn.cfg/eof-hides-reset!CleanEof>

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
        Stack::new(&config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {addr}")).unwrap(), false)
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
    fn a_syn_offers_selective_acknowledgement_only_if_the_stack_is_told_to() {
        let key = crate::keys::encode(&[1; 32]);
        let cfg = config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {A}")).unwrap();
        for sack in [false, true] {
            let mut a = Stack::new(&cfg, sack);
            let _ruby = connect(&mut a, B, 7);
            a.turn();
            let syn = a.transmit().unwrap();
            // The options follow 20 bytes of IP header and 20 of TCP.
            assert_eq!(syn[40..].windows(2).any(|option| option == [4, 2]), sack);
        }
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
    fn an_attempt_that_nobody_answers_times_out() {
        let mut a = stack(A);
        let mut ruby = connect(&mut a, B, 7);
        // Nothing takes what A sends, and A's clock is put on a second at
        // a time.
        let mut status = Vec::new();
        for _ in 0..2 * TCP_TIMEOUT.as_secs() {
            age(&mut a, Duration::from_secs(1));
            a.turn();
            while a.transmit().is_some() {}
            let (bytes, end) = read(&mut ruby);
            status.extend(bytes);
            if end {
                break;
            }
        }
        assert_eq!(status, [status::TIMED_OUT]);
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

    /// Puts a stack's clock on, which makes its connections that much
    /// older.
    fn age(stack: &mut Stack, by: Duration) {
        stack.clock += by;
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
        // The waits go by A's clock, which a stop of this process does not
        // use up.
        let quiet = a.clock;
        while a.clock - quiet < Duration::from_secs(3) {
            settle(&mut a, &mut b);
        }
        client.write_all(b"still here").unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"still here".to_vec(), false));
        // B is gone, and nothing answers what A sends.
        let gone = a.clock;
        while a.clock - gone < Duration::from_secs(3) {
            a.turn();
            while a.transmit().is_some() {}
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(read(&mut client), (vec![], true));
        assert!(a.conns.is_empty());
    }

    #[test]
    fn a_thread_that_stood_still_finds_its_connections_open() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // A's thread finds the system's clock twice the timeout further
        // on, and its own clock goes on by one step.
        let before = a.clock;
        a.time_at(Instant::now() + 2 * TCP_TIMEOUT);
        a.read_at = Instant::now();
        assert_eq!(a.clock, before + STEP);
        settle(&mut a, &mut b);
        client.write_all(b"still here").unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"still here".to_vec(), false));
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
        let ended = a.clock;
        while a.clock - ended < Duration::from_secs(11) {
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
        assert!(!a.finished(), "the dead connection has the time for its last ACK");
        assert_eq!(read(&mut client), (b"bye".to_vec(), true));
        // The tunnel closes with no linger, as Engine::finish has it.
        a.orphan();
        a.abort();
        a.poll();
        let ack = a.transmit().expect("the ACK of the peer's FIN");
        assert!(!is_reset(&ack));
        age(&mut a, LAST_ACK);
        assert!(a.finished());
    }

    #[test]
    fn an_end_that_stops_reading_may_still_write() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.shutdown(Shutdown::Read).unwrap();
        server.write_all(b"unheard").unwrap();
        settle(&mut a, &mut b);
        client.write_all(b"still talking").unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (b"still talking".to_vec(), false));
        assert!(a.conns.len() == 1 && a.conns[0].deaf && b.conns.len() == 1);
    }
}

//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end, and moves bytes between it and the buffers of the TCP
//! socket. The buffers of both are bounded, so each direction has flow
//! control from end to end.

use crate::config::Config;
use crate::packet::{rst, split_fin, syn, without_sack};
use crate::pair::{Gave, Hangup, Pair, Took};
use crate::sock::{Opening, Sock, Up};
use crate::sys::{self, Sent};
use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SDuration, Instant as SInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// A socket holds this many bytes that Ruby wrote, until the peer has
/// acknowledged them.
const SEND_BUF: usize = 256 * 1024;
/// A socket holds this many bytes that the peer sent, until the pair has
/// room for them. A TCP header can give a window of this size and no more
/// unless the window is scaled, so the peer sends this much at the most
/// in one round trip.
///
/// smoltcp gets a scaled window wrong. It rounds the window down to the
/// scale, so the end of the window moves back by a few bytes as the
/// buffer fills. It takes a segment as far as the end that it has on
/// record, which its last ACK gave, and the peer may have sent as far as
/// an end that it was given before. smoltcp drops the bytes between the
/// two, and takes the FIN of that segment all the same. Ruby would read
/// the end of the stream without those bytes. While a window is shut,
/// smoltcp also counts nothing from such a peer as heard, and its
/// timeout would reset a peer that is there. The peer may scale its own
/// window whatever this size is.
const RECV_BUF: usize = 65535;
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

/// A connection is in one of these phases, and a phase holds what the
/// connection has only then. Each time is read from the stack's clock.
enum Phase {
    /// The SYN is sent, and Ruby waits on its end of the pair for the
    /// status.
    Connecting {
        pair: Pair,
        since: Duration,
    },
    /// The socket waits for the handshake that a SYN began. There is no
    /// pair yet.
    Listening {
        listener: u64,
    },
    /// The connection is established. `theirs` is the end of the pair
    /// that the listener has yet to send to Ruby.
    Accepting {
        listener: u64,
        pair: Pair,
        theirs: OwnedFd,
    },
    Open(Open),
    /// The connection is closed to Ruby and has no pair. Its socket stays
    /// until it has sent what it owes the peer.
    Dead {
        since: Duration,
    },
}

/// What an open connection has besides its socket.
struct Open {
    pair: Pair,
    /// When poll first reported a hangup on our end. Either Ruby has
    /// closed its end, or each side has shut down its writing, which poll
    /// does not tell apart. In both cases Ruby has no more to say, and
    /// has been told all that it will be.
    left: Option<Duration>,
    /// Since when the connection has waited for nothing but the peer's
    /// FIN: Ruby has left, and the peer has acknowledged our FIN.
    wait: Option<Duration>,
    /// The tail holds what the peer sent last and Ruby has yet to be
    /// given, once that is taken out of the socket's buffer.
    tail: VecDeque<u8>,
}

impl Phase {
    /// Returns the phase of a connection that has just become open.
    fn open(pair: Pair) -> Phase {
        Phase::Open(Open { pair, left: None, wait: None, tail: VecDeque::new() })
    }
}

/// A step decides one of these for its connection.
enum Fate {
    /// The connection goes on, in this phase.
    Keep(Phase),
    /// Close our end of the pair. The TCP connection has ended by itself.
    Close,
    /// Close our end of the pair, and reset the TCP connection.
    Abort,
}

struct Conn {
    handle: SocketHandle,
    /// The local port that an outbound connection took.
    local_port: Option<u16>,
    phase: Phase,
}

// The module "stream" is what a connection promises to Ruby and to the
// peer. It has no word of sockets or of descriptors, and the model "conn"
// below is checked to keep it.
//
// TLA-stream> \* This is what one connection promises to Ruby and to the peer, whatever
// TLA-stream> \* carries it. A connection has two streams. One goes down, from the peer
// TLA-stream> \* to Ruby, and one goes up, from Ruby to the peer. A state of a stream is
// TLA-stream> \* a record with these fields.
// TLA-stream> \*   src     how many bytes its writer wrote and the stack has yet to pass on
// TLA-stream> \*   dst     how many bytes the stack passed on and its reader has yet to take
// TLA-stream> \*   open    the stack has not ended the stream for its reader
// TLA-stream> \*   done    its writer will write no more
// TLA-stream> \* A state of the connection has the two streams and these fields.
// TLA-stream> \*   cut     the connection is reset, or it timed out
// TLA-stream> \*   gone    the peer cut it, or is silent for good
// TLA-stream> \*   left    Ruby has left, and no more can pass between it and the stack
// TLA-stream> \*   late    Ruby is owed no more time
// TLA-stream> \*   unread  the peer sent bytes that Ruby has not read
// TLA-stream> EXTENDS Naturals
// TLA-stream> \* The stack loses no byte of a stream and adds none, unless the connection
// TLA-stream> \* is cut. A step keeps the bytes, or the reader takes some, or the writer
// TLA-stream> \* gives one. A writer that is done gives no more.
// TLA-stream> Flows(a, b, cut) ==
// TLA-stream>   /\ \/ cut
// TLA-stream>      \/ b.src + b.dst = a.src + a.dst
// TLA-stream>      \/ b.src = a.src /\ b.dst <= a.dst
// TLA-stream>      \/ b.src = a.src + 1 /\ b.dst = a.dst /\ ~a.done
// TLA-stream>   \* It ends a stream once, when the writer is done and all that it wrote
// TLA-stream>   \* is passed on.
// TLA-stream>   /\ ~a.open => ~b.open
// TLA-stream>   /\ a.open /\ ~b.open => cut \/ (b.src = 0 /\ b.done)
// TLA-stream> \* The stack cuts a connection only for a cause. The peer cut it or is
// TLA-stream> \* gone. Or Ruby has left, and its time is up or it left bytes unread.
// TLA-stream> Cuts(a, b) == ~a.cut /\ b.cut => b.gone \/ (a.left /\ (a.late \/ a.unread))
// TLA-stream> Step(a, b) == Flows(a.down, b.down, b.cut) /\ Flows(a.up, b.up, b.cut) /\ Cuts(a, b)
//
// The model "conn" is of one connection for the whole of its life: how
// step answers a Ruby that makes a connection, and hands it one that a
// peer made, how carry moves bytes between the pair and the socket, what
// poll is asked about the pair, and how the connection ends. Its pair is
// the module "pair", in pair.rs, and its socket is the module "sock", in
// sock.rs. The lines of the model are beside the code that they describe,
// and `rake tla` checks them.
//
// TLA-conn@0> EXTENDS Naturals
// TLA-conn@0> CONSTANTS Budget,   \* how many bytes each side may write
// TLA-conn@0>           TxCap,    \* how many bytes the socket holds to send
// TLA-conn@0>           RxCap,    \* how many bytes the socket holds for Ruby
// TLA-conn@0>           PairCap,  \* how many bytes the pair holds each way
// TLA-conn@0>           Fault     \* the fault that a variant puts in, or "none"
// TLA-conn@0> \* The pair is the one that pair.rs describes, and the socket is the one
// TLA-conn@0> \* that sock.rs describes. The model has no more of the kernel or of
// TLA-conn@0> \* smoltcp than those two.
// TLA-conn@0> P == INSTANCE pair
// TLA-conn@0> K == INSTANCE sock
// TLA-conn@0> Min(a, b) == IF a < b THEN a ELSE b
// TLA-conn@0> \* The state is one record, so that a step says what it changes and no more.
// TLA-conn@0> VARIABLE s
// TLA-conn@0> \* A connection begins when Ruby makes it, or when a SYN arrives for a
// TLA-conn@0> \* listener.
// TLA-conn@0> Init == \E first \in {"connecting", "listening"}, r \in BOOLEAN : s = [
// TLA-conn@0>   p       |-> P!New,    \* the pair
// TLA-conn@0>   k       |-> K!New,    \* the socket
// TLA-conn@0>   phase   |-> first,    \* "connecting", "listening", "accepting", "open", "dead" or "removed"
// TLA-conn@0>   old     |-> FALSE,    \* the phase is old: an attempt as smoltcp's timeout, a dead socket as LINGER
// TLA-conn@0>   said    |-> "none",   \* what Ruby was told of the attempt: "ok", "refused" or "timedout"
// TLA-conn@0>   listens |-> TRUE,     \* Ruby has not closed the listener
// TLA-conn@0>   room    |-> first = "connecting" \/ r,  \* the listener's pair has room for a message
// TLA-conn@0>   done    |-> FALSE,    \* Pair::done
// TLA-conn@0>   deaf    |-> FALSE,    \* Pair::deaf
// TLA-conn@0>   told    |-> FALSE,    \* Pair::told
// TLA-conn@0>   left    |-> "no",     \* Open.left is "no", "yes" or "late" (TCP_TIMEOUT ago)
// TLA-conn@0>   wait    |-> "no",     \* Open.wait is "no", "yes" or "late" (FIN_WAIT ago)
// TLA-conn@0>   closing |-> FALSE,    \* Stack.closing
// TLA-conn@0>   at      |-> "idle",   \* where the thread is in a pass over the connection
// TLA-conn@0>   kick    |-> FALSE]    \* poll will return, whatever it reports of the pair
// TLA-conn@0> Early == {"connecting", "listening", "accepting"}
// TLA-conn@0> Live == Early \cup {"open"}
//
// The model takes this much of Ruby, of the peer and of time.
//
// TLA-conn@10> \* Ruby has its end of the pair from the first for a connection that it
// TLA-conn@10> \* makes. Tunnel#connect gives its caller the socket only when the status
// TLA-conn@10> \* has come, so until then Ruby does nothing with its end but close it.
// TLA-conn@10> \* Ruby has its end of a connection that it accepts once the listener has
// TLA-conn@10> \* sent it.
// TLA-conn@10> RubyMoves == CASE s.phase = "connecting" -> P!Closes(s.p)
// TLA-conn@10>                [] s.phase = "open" -> P!Ruby(s.p)
// TLA-conn@10>                [] OTHER -> {}
// TLA-conn@10> RubyActs == \E p \in RubyMoves : s' = [s EXCEPT !.p = p]
// TLA-conn@10> \* The reads among Ruby's moves, which ToRuby has Ruby go on making.
// TLA-conn@10> RubyReads == s.phase = "open" /\ \E p \in P!Reads(s.p) : s' = [s EXCEPT !.p = p]
// TLA-conn@10> \* Ruby may close the listener while a connection waits for it. When Ruby
// TLA-conn@10> \* accepts another connection, the listener's pair has room again, and
// TLA-conn@10> \* the message that Ruby answers with wakes the loop. Other connections
// TLA-conn@10> \* take the room.
// TLA-conn@10> Waiting == s.phase \in {"listening", "accepting"} /\ s.listens
// TLA-conn@10> ListenerCloses == Waiting /\ s' = [s EXCEPT !.listens = FALSE, !.kick = TRUE]
// TLA-conn@10> RubyAccepts == Waiting /\ ~s.room /\ s' = [s EXCEPT !.room = TRUE, !.kick = TRUE]
// TLA-conn@10> RoomGoes == Waiting /\ s.room /\ s' = [s EXCEPT !.room = FALSE]
// TLA-conn@10> \* A packet is taken in between two passes, and it wakes the loop.
// TLA-conn@10> \* Stack::unlisten removes a socket whose handshake the peer reset, before
// TLA-conn@10> \* step sees it.
// TLA-conn@10> Arrives(k) == [s EXCEPT !.k = k, !.kick = TRUE,
// TLA-conn@10>                         !.phase = IF @ = "listening" /\ s.k.pending /\ k.cut THEN "removed" ELSE @]
// TLA-conn@10> PeerPacket == s.at = "idle" /\ s.phase # "removed" /\ \E k \in K!Packet(s.k) : s' = Arrives(k)
// TLA-conn@10> \* The acknowledgements among the packets, which ToPeer has the peer go
// TLA-conn@10> \* on sending.
// TLA-conn@10> PeerAcks == /\ s.at = "idle" /\ s.phase # "removed"
// TLA-conn@10>             /\ \E k \in K!PeerAcks(s.k) \cup K!PeerAcksFin(s.k) : s' = Arrives(k)
// TLA-conn@10> PeerSilent == s.phase # "removed" /\ \E k \in K!Silence(s.k) : s' = [s EXCEPT !.k = k]
// TLA-conn@10> \* Time passes. A tick or a timer of smoltcp turns the loop, and the
// TLA-conn@10> \* thread reads the clock then, so each of these steps wakes the loop. An
// TLA-conn@10> \* attempt that fails is taken for refused or for timed out by how old it
// TLA-conn@10> \* is, and smoltcp's timeout comes when it is old. The timeout of a
// TLA-conn@10> \* socket takes effect between two passes.
// TLA-conn@10> TimesOut == /\ s.at = "idle" /\ s.phase # "removed" /\ (s.phase = "connecting" => s.old)
// TLA-conn@10>             /\ \E k \in K!TimesOut(s.k) : s' = [s EXCEPT !.k = k, !.kick = TRUE]
// TLA-conn@10> Forgets == /\ s.at = "idle" /\ s.phase = "open"
// TLA-conn@10>            /\ \E k \in K!Forgets(s.k) : s' = [s EXCEPT !.k = k, !.kick = TRUE]
// TLA-conn@10> \* smoltcp delays an ACK for less long than LINGER, so a dead socket is old
// TLA-conn@10> \* only when it owes nothing.
// TLA-conn@10> Ages == /\ ~s.old /\ (s.phase = "connecting" \/ (s.phase = "dead" /\ s.k.owed = "none"))
// TLA-conn@10>         /\ s' = [s EXCEPT !.old = TRUE, !.kick = TRUE]
// TLA-conn@10> Late == /\ s.phase = "open"
// TLA-conn@10>         /\ \/ s.left = "yes" /\ s' = [s EXCEPT !.left = "late", !.kick = TRUE]
// TLA-conn@10>            \/ s.wait = "yes" /\ s' = [s EXCEPT !.wait = "late", !.kick = TRUE]

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
    /// A connection that waits for its listener names it by this, so that
    /// it is not taken for a connection of a later listener on the port.
    id: u64,
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
    /// How many listeners there have been.
    listened: u64,
    local_ports: HashSet<u16>,
    addrs: Vec<IpAddr>,
    /// The stack's time, and when it was last read.
    clock: Duration,
    read_at: Instant,
    /// Selective acknowledgement is left on offer in the SYNs.
    sack: bool,
    /// The tunnel is closing, and every pair is shut down.
    closing: bool,
}

fn socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; RECV_BUF]), tcp::SocketBuffer::new(vec![0; SEND_BUF]));
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
            listened: 0,
            local_ports: HashSet::new(),
            addrs: cfg.addrs.clone(),
            clock: Duration::ZERO,
            read_at: Instant::now(),
            sack,
            closing: false,
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
        // smoltcp takes a segment as far as the end of the window that it
        // has on record, and it takes the FIN of a segment that it cut
        // there. Ruby would then read the end of the stream without the
        // bytes that were cut. A peer can have sent past that end. A
        // keep-alive carries the window as it is then, and so does a probe
        // of the peer's window, and smoltcp keeps no record of either. And
        // after a SYN of its own, smoltcp has the end on record a byte
        // short until its first ACK has left. So a FIN comes to smoltcp in
        // a packet of its own, after its data. smoltcp passes over a FIN
        // that follows bytes which it does not have, and the peer sends
        // the FIN again with those bytes.
        let fin = split_fin(&mut packet);
        self.link.rx.push_back(packet);
        self.link.rx.extend(fin);
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
        let phase = Phase::Connecting { pair: Pair::new(fd), since: self.clock };
        self.conns.push(Conn { handle, local_port: Some(local), phase });
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
        self.listened += 1;
        self.listeners.push(Listener { id: self.listened, port, ctl, backlog, unaccepted: 0 });
    }

    /// Stops the listening on each port whose listener Ruby has closed. A
    /// connection that Ruby was not sent then finds no listener, and is
    /// reset at its next step.
    fn reap(&mut self) {
        self.listeners.retain(|l| !sys::ended(l.ctl.as_raw_fd()));
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
        let waits = |c: &&Conn| matches!(c.phase, Phase::Listening { listener } | Phase::Accepting { listener, .. } if listener == l.id);
        let pending = l.unaccepted + self.conns.iter().filter(waits).count();
        let mut s = socket();
        if pending >= l.backlog || s.listen(port).is_err() {
            return Welcome::Full;
        }
        let handle = self.sockets.add(s);
        self.conns.push(Conn { handle, local_port: None, phase: Phase::Listening { listener: l.id } });
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
            let listens = matches!(c.phase, Phase::Listening { .. })
                && sockets.get::<tcp::Socket>(c.handle).state() == tcp::State::Listen;
            if listens {
                sockets.remove(c.handle);
            }
            !listens
        });
    }

    /// Returns how many connections there are: those that the stack is
    /// making, and those that are made and have not ended.
    pub fn connections(&self) -> usize {
        self.conns.iter().filter(|c| !matches!(c.phase, Phase::Listening { .. } | Phase::Dead { .. })).count()
    }

    /// Describes every connection, each in two lines. The first is what
    /// the stack knows of it. The second is smoltcp's account of the
    /// socket, without the bytes in its buffers.
    pub fn describe(&self, text: &mut String) {
        for c in &self.conns {
            let (phase, pair) = match &c.phase {
                Phase::Connecting { pair, .. } => ("connecting", Some(pair)),
                Phase::Listening { .. } => ("listening", None),
                Phase::Accepting { pair, .. } => ("accepting", Some(pair)),
                Phase::Open(open) => ("open", Some(&open.pair)),
                Phase::Dead { .. } => ("dead", None),
            };
            let (tail, left) = match &c.phase {
                Phase::Open(open) => (open.tail.len(), open.left.is_some()),
                _ => (0, false),
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
                s.recv_queue() + tail,
                pair.map_or(0, Pair::waiting),
                if pair.is_some_and(Pair::done) { ", no more comes from Ruby" } else { "" },
                if pair.is_some_and(Pair::told) { ", the peer has ended its stream" } else { "" },
                if left { ", Ruby is gone" } else { "" },
            );
            let mut detail = format!("{s:?}");
            while let Some(from) = detail.find("Owned([") {
                let to = detail[from..].find("])").map_or(detail.len(), |to| from + to + 2);
                detail.replace_range(from..to, "..");
            }
            let _ = writeln!(text, "  {detail}");
        }
    }

    // TLA-conn> \* Every turn of the loop has each socket send what it owes. smoltcp may
    // TLA-conn> \* delay an ACK past the turn.
    // TLA-conn> Dispatch == s.phase # "removed" /\ s.k.owed # "none" /\ s' = [s EXCEPT !.k.owed = "none"]
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

    // TLA-conn@70> \* The thread may turn the loop at any time, as it does for the tick and
    // TLA-conn@70> \* for another connection, and a turn makes a pass over this connection.
    // TLA-conn@70> \* It does turn when poll has a cause to return.
    // TLA-conn@70> Turn == s.at = "idle" /\ s.phase \in Live /\ s' = [s EXCEPT !.at = First(s), !.kick = FALSE]
    // TLA-conn@70> Wake == (s.kick \/ FdReady(s)) /\ Turn
    // TLA-conn@70> Step == s.at # "idle" /\ s' = StepAt(s)
    /// Takes in the packets that arrived, moves each connection on, has
    /// every socket send what it has to send, and removes the connections
    /// that owe the peer nothing more. So an ACK tells the peer of the
    /// room that there is once Ruby has been given its bytes, and what
    /// Ruby wrote leaves in the turn that took it.
    ///
    /// A turn leaves each connection at rest. Nothing more happens to one
    /// until a packet arrives for it, Ruby does what poll reports of its
    /// pair or its listener, or a timer runs out. So the caller may wait
    /// for the first of those.
    pub fn turn(&mut self) {
        // The connections' times are judged by the clock as it is now.
        self.now();
        self.ingress();
        self.pump();
        self.poll();
        self.sweep();
    }

    // TLA-conn> \* The tunnel is closing. orphan shuts down each pair both ways, and
    // TLA-conn> \* leaves no listener. The loop turns at once.
    // TLA-conn> Orphan == /\ s.at = "idle" /\ ~s.closing /\ s.phase # "removed"
    // TLA-conn>           /\ s' = [s EXCEPT !.closing = TRUE, !.kick = TRUE,
    // TLA-conn>                             !.listens = @ /\ s.phase \notin {"listening", "accepting"},
    // TLA-conn>                             !.p = IF s.phase \in {"connecting", "open"} THEN P!Shut(@) ELSE @]
    /// Stops the listening, and leaves every connection as it would be if
    /// Ruby had closed its end. The tunnel is closing.
    pub fn orphan(&mut self) {
        // A connection that Ruby was not sent finds no listener, and is
        // reset at its next step.
        self.listeners.clear();
        self.closing = true;
        for c in &self.conns {
            // To our end, the pair is then what a pair is whose other
            // end Ruby has closed.
            if let Phase::Connecting { pair, .. } | Phase::Open(Open { pair, .. }) = &c.phase {
                pair.shut();
            }
        }
    }

    /// Says whether every connection has ended, and has had the time to
    /// send its last ACK.
    pub fn finished(&self) -> bool {
        self.conns.iter().all(|c| matches!(c.phase, Phase::Dead { since } if self.clock - since >= LAST_ACK))
    }

    // TLA-conn> \* The linger is over. abort resets a connection that has not ended. The
    // TLA-conn> \* poll that follows sends what every socket owes, an ACK that was delayed
    // TLA-conn> \* among it, and the thread ends.
    // TLA-conn> Finish == /\ s.at = "idle" /\ s.closing /\ s.phase # "removed"
    // TLA-conn>           /\ LET k == IF s.phase = "dead" THEN s.k ELSE K!Abort(s.k)
    // TLA-conn>              IN s' = [s EXCEPT !.phase = "removed", !.k = [k EXCEPT !.owed = "none"]]
    /// Resets every connection that has not ended. The resets leave at
    /// the next poll.
    pub fn abort(&mut self) {
        for c in self.conns.iter().filter(|c| !matches!(c.phase, Phase::Dead { .. })) {
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

    /// Moves every connection as far as it will go.
    fn pump(&mut self) {
        // Ruby may have accepted connections, or closed a listener. A
        // connection that waits for its listener is stepped after that.
        for l in &mut self.listeners {
            l.credit();
        }
        self.reap();
        for c in &mut self.conns {
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            // The step takes the phase and gives back the phase to go on
            // in. If it gives none back, the connection is over for Ruby,
            // and what the phase held is closed: our end of the pair, and
            // the other end if the listener had yet to send it. The
            // socket has a reset or a last ACK to send, and must stay
            // until it has sent it.
            let phase = std::mem::replace(&mut c.phase, Phase::Dead { since: self.clock });
            match step(phase, s, &mut self.listeners, self.clock, self.closing) {
                Fate::Keep(phase) => c.phase = phase,
                Fate::Close => {}
                Fate::Abort => s.abort(),
            }
        }
    }

    // TLA-conn> \* sweep removes a dead connection when its socket was reset and has sent
    // TLA-conn> \* the reset, or when the peer's FIN has had long enough to be
    // TLA-conn> \* acknowledged.
    // TLA-conn> Sweep == /\ s.phase = "dead" /\ (K!Silent(s.k) \/ (s.old /\ s.k.owed = "none"))
    // TLA-conn>          /\ s' = [s EXCEPT !.phase = "removed"]
    // TLA-conn> \* smoltcp also forgets a socket whose FIN the peer acknowledged last, and
    // TLA-conn> \* sweep may find that one silent sooner.
    // TLA-conn> SweepEarly == /\ s.phase = "dead" /\ ~s.k.cut /\ s.k.owed = "none"
    // TLA-conn>               /\ s' = [s EXCEPT !.phase = "removed"]
    /// Removes each dead connection whose socket has sent what it owed.
    /// The sockets have just sent, so one that was reset in this turn goes
    /// in this turn.
    fn sweep(&mut self) {
        let (sockets, ports, now) = (&mut self.sockets, &mut self.local_ports, self.clock);
        self.conns.retain(|c| {
            let Phase::Dead { since } = c.phase else { return true };
            // A socket in TIME-WAIT may still owe the peer's FIN an ACK,
            // which smoltcp may delay.
            if !Sock::silent(sockets.get::<tcp::Socket>(c.handle)) && now - since < LINGER {
                return true;
            }
            sockets.remove(c.handle);
            if let Some(port) = c.local_port {
                ports.remove(&port);
            }
            false
        });
    }

    // TLA-conn> \* poll_fds. The pair is read while the socket has room, and written
    // TLA-conn> \* while the socket holds bytes that the pair has not refused. A
    // TLA-conn> \* descriptor with neither asked of it is watched for a hangup, until the
    // TLA-conn> \* hangup has been seen.
    // TLA-conn> AskIn(t) == ~t.done /\ K!HasRoom(t.k) /\ Fault # "reads unasked"
    // TLA-conn> AskOut(t) == K!Holds(t.k) /\ (~t.deaf \/ Fault = "deaf asks") /\ Fault # "writes unasked"
    // TLA-conn> Watched(t) == \/ AskIn(t) \/ AskOut(t)
    // TLA-conn>               \/ t.left = "no" /\ Fault # "hangup unwatched"
    // TLA-conn>               \/ Fault = "hangup always watched"
    // TLA-conn> \* FdReady says whether poll returns for the descriptor. It reports a
    // TLA-conn> \* hangup, and bytes that Ruby left unread, whatever it is asked. A
    // TLA-conn> \* connection that Ruby makes is watched for Ruby giving it up.
    // TLA-conn> FdReady(t) == CASE t.phase = "open" -> /\ Watched(t)
    // TLA-conn>                                        /\ \/ AskIn(t) /\ P!Readable(t.p)
    // TLA-conn>                                           \/ AskOut(t) /\ P!Writable(t.p)
    // TLA-conn>                                           \/ P!HungUp(t.p) \/ P!Unread(t.p)
    // TLA-conn>                 [] t.phase = "connecting" -> P!HungUp(t.p)
    // TLA-conn>                 [] OTHER -> FALSE
    /// Adds to `fds` each descriptor that poll should watch for the
    /// connections and the listeners.
    pub fn poll_fds(&self, fds: &mut Vec<libc::pollfd>) {
        // A listener is watched for Ruby accepting a connection and for
        // Ruby closing it.
        for l in &self.listeners {
            fds.push(libc::pollfd { fd: l.ctl.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        for c in &self.conns {
            // poll reports a hangup whether asked or not. So a descriptor
            // with no events asked of it is watched for Ruby closing its
            // end, and for nothing else.
            let (pair, events) = match &c.phase {
                Phase::Listening { .. } | Phase::Accepting { .. } | Phase::Dead { .. } => continue,
                // Ruby may write before it has the status, and nothing
                // reads that yet. So poll is not asked whether there is
                // anything to read, for which it would return for ever.
                Phase::Connecting { pair, .. } => (pair, 0),
                Phase::Open(Open { pair, left, tail, .. }) => {
                    // The pair is read while the socket has room, and
                    // written while the socket has bytes for Ruby, unless
                    // the pair has refused them.
                    let (room, holds) = Sock::asks(self.sockets.get::<tcp::Socket>(c.handle), tail);
                    let read = if !pair.done() && room { libc::POLLIN } else { 0 };
                    let write = if holds && !pair.deaf() { libc::POLLOUT } else { 0 };
                    // Once the hangup has been seen, poll would return
                    // for it for ever.
                    if read | write == 0 && left.is_some() {
                        continue;
                    }
                    (pair, read | write)
                }
            };
            fds.push(libc::pollfd { fd: pair.raw(), events, revents: 0 });
        }
    }
}

// TLA-conn@20> \* A pass ends in one of these ways. A connection that is closed or reset
// TLA-conn@20> \* keeps its socket, as Phase::Dead, until the socket has sent what it owes.
// TLA-conn@20> Rest(t) == [t EXCEPT !.at = "idle"]
// TLA-conn@20> Dead(t) == [t EXCEPT !.phase = IF Fault = "remove at once" THEN "removed" ELSE "dead",
// TLA-conn@20>                      !.old = FALSE, !.at = "idle"]
// TLA-conn@20> Close(t) == Dead(t)
// TLA-conn@20> Abort(t) == Dead([t EXCEPT !.k = K!Abort(@)])
// TLA-conn> \* step, for a connection that is not open yet. Ruby is told of a
// TLA-conn> \* connection once, when its handshake is over: with the status of one
// TLA-conn> \* that it makes, or with the descriptor of one that it accepts. A
// TLA-conn> \* connection that becomes open is carried in the same pass.
// TLA-conn> Begin(t) ==
// TLA-conn>   CASE t.phase = "connecting" ->
// TLA-conn>          IF P!HungUp(t.p) THEN Abort(t)
// TLA-conn>          ELSE IF K!Opening(t.k) = "done" \/ (Fault = "greets early" /\ K!Opening(t.k) = "pending")
// TLA-conn>               THEN [t EXCEPT !.said = "ok", !.phase = "open", !.old = FALSE, !.at = "take"]
// TLA-conn>          ELSE IF K!Opening(t.k) = "failed"
// TLA-conn>               THEN Close([t EXCEPT !.said = IF t.old THEN "timedout" ELSE "refused"])
// TLA-conn>          ELSE Rest(t)
// TLA-conn>     [] t.phase = "listening" ->
// TLA-conn>          IF ~t.listens THEN Abort(t)
// TLA-conn>          ELSE IF K!Opening(t.k) = "done" THEN [t EXCEPT !.phase = "accepting"]
// TLA-conn>          ELSE IF K!Opening(t.k) = "failed" /\ Fault # "keeps a failure" THEN Close(t)
// TLA-conn>          ELSE Rest(t)
// TLA-conn>     [] t.phase = "accepting" ->
// TLA-conn>          IF ~t.listens \/ K!Opening(t.k) = "failed" THEN Abort(t)
// TLA-conn>          ELSE IF t.room THEN [t EXCEPT !.said = "ok", !.phase = "open", !.at = "take"]
// TLA-conn>          ELSE Rest(t)
/// Moves one connection as far as it will go, through each phase that it
/// can leave now, and says what becomes of it.
fn step(mut phase: Phase, s: &mut tcp::Socket, listeners: &mut [Listener], now: Duration, closing: bool) -> Fate {
    loop {
        phase = match phase {
            // sweep removes it.
            Phase::Dead { .. } => return Fate::Keep(phase),
            // Ruby gave up waiting, and closed its end. Or the tunnel is
            // closing, and has shut the pair down.
            Phase::Connecting { pair, .. } if pair.hangup() != Hangup::No => return Fate::Abort,
            Phase::Connecting { pair, since } => match Sock::opening(s) {
                // The peer answers a SYN with a bare SYN if it was
                // connecting to us at the same moment, and the handshake
                // is not over.
                Opening::Pending => return Fate::Keep(Phase::Connecting { pair, since }),
                Opening::Failed => {
                    // smoltcp does not say whether a reset or its timeout
                    // closed the socket, so the time taken has to.
                    let late = now - since + Duration::from_secs(1) >= TCP_TIMEOUT;
                    pair.say(if late { status::TIMED_OUT } else { status::REFUSED });
                    return Fate::Close;
                }
                Opening::Done => {
                    pair.say(status::OK);
                    Phase::open(pair)
                }
            },
            Phase::Listening { listener } => match Sock::opening(s) {
                // Ruby closed the listener.
                _ if listeners.iter().all(|l| l.id != listener) => return Fate::Abort,
                Opening::Pending => return Fate::Keep(phase),
                // The peer left the handshake unfinished, or it finished
                // the handshake and reset the connection at once.
                Opening::Failed => return Fate::Close,
                Opening::Done => match sys::socketpair(libc::SOCK_STREAM) {
                    Ok((ours, theirs)) => Phase::Accepting { listener, pair: Pair::new(ours), theirs },
                    // The system has no descriptors to spare.
                    Err(_) => return Fate::Abort,
                },
            },
            Phase::Accepting { listener, pair, theirs } => {
                // Ruby may have closed the listener, and the peer may have
                // reset the connection already.
                let l = listeners.iter_mut().find(|l| l.id == listener);
                let (Some(l), Some(from)) = (l, s.remote_endpoint()) else { return Fate::Abort };
                let message = format!("{} {}", from.addr, from.port);
                match sys::send_fd(l.ctl.as_raw_fd(), message.as_bytes(), theirs.as_raw_fd()) {
                    Sent::Ok => {
                        l.unaccepted += 1;
                        Phase::open(pair)
                    }
                    // The listener's pair has no room. Ruby makes room
                    // when it accepts a connection, and poll reports the
                    // answer that it then sends.
                    Sent::Full => return Fate::Keep(Phase::Accepting { listener, pair, theirs }),
                    Sent::Gone => return Fate::Abort,
                }
            }
            Phase::Open(open) => return carry(open, s, now, closing),
        };
    }
}

/// Moves bytes each way for an open connection, and passes on the end of
/// each direction.
fn carry(mut open: Open, s: &mut tcp::Socket, now: Duration, closing: bool) -> Fate {
    let Open { pair, left, wait, tail } = &mut open;
    // The socket's contract has the tail, and carry has the rest.
    let s = &mut Sock::new(s, tail);

    // TLA-conn> \* A pass of carry is four steps, and each makes one kind of call on the
    // TLA-conn> \* pair. Ruby may act between two calls.
    // TLA-conn> \*
    // TLA-conn> \* The first step takes what Ruby wrote. One read moves as many bytes as
    // TLA-conn> \* the socket has room for, and the step comes again until a read moves
    // TLA-conn> \* none. If the stream to the peer has ended and Ruby has not ended its
    // TLA-conn> \* own, the peer cut the connection, and the step stops what Ruby writes.
    // TLA-conn> \* Our FIN follows what Ruby wrote, and it waits until the peer has
    // TLA-conn> \* acknowledged all of that.
    // TLA-conn> Fin(t) == IF t.k.up = "open" /\ t.done /\ (K!AllAcked(t.k) \/ Fault = "early fin")
    // TLA-conn>           THEN [t EXCEPT !.k = K!End(@)] ELSE t
    // TLA-conn> Onward(t) == [Fin(t) EXCEPT !.at = "give"]
    // TLA-conn> Take(t) ==
    // TLA-conn>   IF ~t.done /\ t.k.up # "open" THEN Onward([t EXCEPT !.done = TRUE, !.p = P!Stop(@)])
    // TLA-conn>   ELSE IF t.done \/ ~K!HasRoom(t.k) THEN Onward(t)
    // TLA-conn>   ELSE CASE P!Read(t.p) = "bytes" -> LET n == Min(t.p.fromRuby, K!Room(t.k))
    // TLA-conn>                                       IN [t EXCEPT !.p = P!Took(@, n), !.k = K!Filled(@, n)]
    // TLA-conn>          [] P!Read(t.p) = "end" -> Onward([t EXCEPT !.done = TRUE])
    // TLA-conn>          [] P!Read(t.p) = "reset" -> Abort([t EXCEPT !.p = P!Heard(@)])
    // TLA-conn>          [] OTHER -> Onward(t)
    if !pair.done() && s.up() != Up::Open {
        // Nothing that Ruby writes from now on can be sent. A write by
        // Ruby then fails, as a write to a TCP socket does once it is
        // reset.
        pair.stop();
    }
    while !pair.done() && s.has_room() {
        match s.fill(|buf| pair.read(buf)) {
            Some(Took::Bytes(_)) => {}
            // The peer sent the bytes that Ruby left unread, and it is
            // reset, as a TCP socket of the kernel resets it when it is
            // closed with bytes unread.
            Some(Took::Reset) => return Fate::Abort,
            Some(Took::End | Took::Nothing) | None => break,
        }
    }
    if s.up() == Up::Open && pair.done() && s.all_acknowledged() {
        s.end();
    }

    // TLA-conn> \* The second step gives Ruby what the socket holds, for as much as the
    // TLA-conn> \* pair has room. When the pair refuses a write, the socket keeps what it
    // TLA-conn> \* holds, and carry writes no more.
    // TLA-conn> Give(t) ==
    // TLA-conn>   IF t.deaf \/ ~K!Holds(t.k) THEN [t EXCEPT !.at = "end"]
    // TLA-conn>   ELSE CASE P!Write(t.p) = "bytes" -> LET n == Min(t.k.rx, PairCap - t.p.forRuby)
    // TLA-conn>                                        IN [t EXCEPT !.k = K!Drained(@, n), !.p = P!Gave(@, n)]
    // TLA-conn>          [] P!Write(t.p) = "refused" ->
    // TLA-conn>               IF Fault = "drops" THEN [t EXCEPT !.k = K!Drained(@, t.k.rx), !.at = "end"]
    // TLA-conn>               ELSE [t EXCEPT !.deaf = TRUE, !.at = "end"]
    // TLA-conn>          [] OTHER -> [t EXCEPT !.at = "end"]
    // A TCP socket of the kernel keeps such bytes too, and the peer is
    // held once the socket is full. Nothing is dropped while the
    // connection lasts.
    while !pair.deaf() && s.holds() {
        if !matches!(s.drain(|buf| pair.write(buf)), Some(Gave::Bytes(_))) {
            break;
        }
    }

    // TLA-conn> \* The third step ends what Ruby reads, when the peer has ended its
    // TLA-conn> \* stream and Ruby has been given all of it.
    // TLA-conn> End(t) == IF ~t.told /\ ~t.k.down /\ ~K!Holds(t.k)
    // TLA-conn>           THEN [t EXCEPT !.told = TRUE, !.p = P!End(@), !.at = "judge"]
    // TLA-conn>           ELSE [t EXCEPT !.at = "judge"]
    if !pair.told() && !s.down_open() && !s.holds() {
        pair.end();
    }

    // TLA-conn> \* The last step asks poll whether Ruby has left, and decides what becomes
    // TLA-conn> \* of the connection. The two times of a connection that Ruby has left
    // TLA-conn> \* begin here.
    // TLA-conn> Judge(t) ==
    // TLA-conn>   LET u == [t EXCEPT !.left = IF @ = "no" /\ P!HungUp(t.p) THEN "yes" ELSE @]
    // TLA-conn>       acked == u.left # "no" /\ u.k.up = "ended" /\ u.k.down
    // TLA-conn>       v == [u EXCEPT !.wait = IF @ = "no" /\ acked THEN "yes" ELSE @]
    // TLA-conn>   IN  IF t.left = "no" /\ P!HungUp(t.p) /\ P!Unread(t.p) THEN Abort(t)
    // TLA-conn>       ELSE IF v.k.up = "ended" /\ ~v.k.down /\ (v.told \/ Fault = "early close") THEN Close(v)
    // TLA-conn>       ELSE IF v.left # "no" /\ K!Holds(v.k) THEN Abort(v)
    // TLA-conn>       ELSE IF v.k.up = "ended" /\ v.k.down /\ (v.closing \/ v.wait = "late") THEN Abort(v)
    // TLA-conn>       ELSE IF v.left = "late" /\ Fault # "no deadline" THEN Abort(v)
    // TLA-conn>       ELSE Rest(v)
    if left.is_none() {
        match pair.hangup() {
            Hangup::No => {}
            Hangup::Yes => *left = Some(now),
            // The peer sent those bytes too, and it is reset for them.
            Hangup::Unread => return Fate::Abort,
        }
    }
    // The peer's time to end its stream begins when Ruby has left and the
    // peer has acknowledged our FIN, whichever comes later.
    if wait.is_none() && left.is_some() && s.up() == Up::Ended && s.down_open() {
        *wait = Some(now);
    }
    // An orphan is a connection that nobody is left to use on Ruby's side.
    let orphaned = left.map(|since| now - since);
    let waited = wait.map(|since| now - since);
    match (s.up(), s.down_open()) {
        // Each stream has ended, and each end has been told.
        (Up::Ended, false) if pair.told() => Fate::Close,
        // Ruby has left, and the socket holds bytes that it did not take.
        // The peer is reset, as it is for bytes that Ruby left unread in
        // the pair.
        _ if left.is_some() && s.holds() => Fate::Abort,
        // The peer has all that Ruby wrote, and is given a while to end
        // its stream too. What it sends in that time is reset above, for
        // want of anyone to read it. A tunnel that is closing does not
        // wait.
        (Up::Ended, true) if closing || waited.is_some_and(|age| age >= FIN_WAIT) => Fate::Abort,
        // TCP waits for as long as the peer answers, and a peer may hold
        // its window shut for ever, or take a byte at a time. An orphan is
        // not kept that long: it has as long as a silent peer is given.
        _ if orphaned.is_some_and(|age| age >= TCP_TIMEOUT) => Fate::Abort,
        _ => Fate::Keep(Phase::Open(open)),
    }
}

// TLA-conn@60> StepAt(t) == CASE t.at = "begin" -> Begin(t) [] t.at = "take" -> Take(t) [] t.at = "give" -> Give(t)
// TLA-conn@60>                [] t.at = "end" -> End(t) [] t.at = "judge" -> Judge(t)
// TLA-conn@60> First(t) == IF t.phase = "open" THEN "take" ELSE "begin"
// TLA-conn@60> \* A whole pass, as it goes when Ruby does nothing meanwhile.
// TLA-conn@60> RECURSIVE Run(_)
// TLA-conn@60> Run(t) == IF t.at = "idle" THEN t ELSE Run(StepAt(t))
// TLA-conn@60> Pass(t) == Run([t EXCEPT !.at = First(t)])
//
// TLA-conn@90> Loop == Wake \/ Step \/ Dispatch \/ Sweep
// TLA-conn@90> Clock == Ages \/ Late
// TLA-conn@90> Timers == TimesOut \/ Forgets \/ Finish
// TLA-conn@90> Next == \/ RubyActs \/ ListenerCloses \/ RubyAccepts \/ RoomGoes \/ PeerPacket \/ PeerSilent
// TLA-conn@90>         \/ Orphan \/ Timers \/ Clock \/ Loop \/ Turn \/ SweepEarly
// TLA-conn@90> \* The loop and the clock run when they can. A timer of smoltcp takes
// TLA-conn@90> \* effect between two passes, and it does in the end, however often the
// TLA-conn@90> \* loop turns. Ruby and the peer owe nothing: each may stop at any point
// TLA-conn@90> \* and never move again.
// TLA-conn@90> Spec == Init /\ [][Next]_s /\ WF_s(Loop) /\ WF_s(Clock) /\ SF_s(Timers)
// TLA-conn@90>
// TLA-conn@90> \* A socket is not removed while it owes the peer a reset or an ACK.
// TLA-conn@90> RemovedClean == s.phase = "removed" => s.k.owed = "none"
// TLA-conn@90> \* Both streams of a dead connection's socket have ended.
// TLA-conn@90> DeadEnds == s.phase = "dead" => s.k.up = "ended" /\ ~s.k.down
// TLA-conn@90> \* carry passes on the end of the peer's stream only when Ruby has been
// TLA-conn@90> \* given all that the peer sent.
// TLA-conn@90> NoneWithheld == s.told => s.k.rx = 0
// TLA-conn@90> \* The socket has nothing left to send when its FIN is queued. smoltcp
// TLA-conn@90> \* does not send a FIN well behind data that a shut window holds back.
// TLA-conn@90> FinIsBare == s.k.up = "ending" => s.k.tx = 0
// TLA-conn@90> \* When poll would wait, a pass would change nothing. So no connection
// TLA-conn@90> \* waits for the tick but for a time of its own. One thing does wait for
// TLA-conn@90> \* the next turn: poll reports later than a write would find it that the
// TLA-conn@90> \* pair takes bytes, and it does not report that the pair refuses them.
// TLA-conn@90> Asleep(t) == t.phase \in Live /\ t.at = "idle" /\ ~t.kick /\ ~FdReady(t)
// TLA-conn@90> NoMissedWake == Asleep(s) => Pass(s) = s \/ (s.phase = "open" /\ AskOut(s) /\ P!Write(s.p) # "full")
// TLA-conn@90> \* When poll returns for the descriptor, a pass changes something. So the
// TLA-conn@90> \* loop does not spin on the descriptor.
// TLA-conn@90> NoSpin == s.phase \in Live /\ s.at = "idle" /\ FdReady(s) => Pass(s) # s
// TLA-conn@90> \* An open connection is one whose handshake is over, and Ruby has been
// TLA-conn@90> \* told so. Ruby is told of nothing else before the attempt is over, and
// TLA-conn@90> \* is told once.
// TLA-conn@90> OpenIsGreeted == s.phase = "open" => ~s.k.pending /\ s.said = "ok"
// TLA-conn@90> SaidAtTheEnd == /\ s.phase \in Early => s.said = "none"
// TLA-conn@90>                 /\ s.said \in {"refused", "timedout"} => s.phase \in {"dead", "removed"}
// TLA-conn@90> SaidOnce == [][s.said # "none" => s'.said = s.said]_s
// TLA-conn@90> \* What the promise sees of this model. Ruby has left when no more can go
// TLA-conn@90> \* either way through the pair, or when it has closed the listener of a
// TLA-conn@90> \* connection that it was not sent. It is owed no time for a connection
// TLA-conn@90> \* that is not open yet, nor once the tunnel closes.
// TLA-conn@90> Seen == [down |-> [src |-> IF s.phase \in Live THEN s.k.rx ELSE 0, dst |-> s.p.forRuby,
// TLA-conn@90>                    open |-> s.phase \in Live /\ ~s.told, done |-> ~s.k.down],
// TLA-conn@90>          up |-> [src |-> s.p.fromRuby, dst |-> IF s.phase \in Live THEN s.k.tx ELSE 0,
// TLA-conn@90>                  open |-> s.phase \in Live /\ s.k.up = "open", done |-> s.done],
// TLA-conn@90>          cut |-> s.k.cut, gone |-> s.k.gone,
// TLA-conn@90>          left |-> P!HungUp(s.p) \/ ~s.listens,
// TLA-conn@90>          late |-> s.closing \/ s.left = "late" \/ s.wait = "late" \/ s.phase \in Early,
// TLA-conn@90>          unread |-> K!Holds(s.k) \/ P!Unread(s.p)]
// TLA-conn@90> Promise == INSTANCE stream
// TLA-conn@90> \* Every step of this model is a step that the promise allows.
// TLA-conn@90> Kept == [][Promise!Step(Seen, Seen')]_s
// TLA-conn@90> \* A dead connection's socket goes, whether or not Ruby ever closes its end.
// TLA-conn@90> DeadGoes == s.phase = "dead" ~> s.phase = "removed"
// TLA-conn@90> \* If a peer is silent for good, both streams of its socket end, or it goes.
// TLA-conn@90> SilenceEnds == s.k.gone ~> (s.k.up = "ended" /\ ~s.k.down) \/ s.phase = "removed"
// TLA-conn@90> \* Once Ruby has closed its end, the connection is let go, whatever the
// TLA-conn@90> \* peer does or fails to do.
// TLA-conn@90> LetGo == s.p.gone = "yes" ~> s.phase = "removed"
// TLA-conn@90> \* An attempt that failed leaves no socket, and neither does one whose
// TLA-conn@90> \* listener Ruby closed before it was open.
// TLA-conn@90> NotBegun == s.phase \in Early /\ (s.k.cut \/ ~s.listens) ~> s.phase = "removed"
// TLA-conn@90> \* Ruby has its answer when the handshake is over, unless it left.
// TLA-conn@90> Answered == s.phase = "connecting" /\ ~s.k.pending ~> s.phase # "connecting"
// TLA-conn@90> \* If Ruby keeps reading, it is given what the socket holds, and then the
// TLA-conn@90> \* end of the peer's stream, unless the connection ends or the pair
// TLA-conn@90> \* refuses.
// TLA-conn@90> ToRuby == WF_s(RubyReads) =>
// TLA-conn@90>             (s.phase = "open" /\ (K!Holds(s.k) \/ ~s.k.down)
// TLA-conn@90>                ~> \/ ~K!Holds(s.k) /\ (s.k.down \/ s.told)
// TLA-conn@90>                   \/ s.phase # "open" \/ P!Write(s.p) = "refused")
// TLA-conn@90> \* If the peer keeps acknowledging, it is sent what Ruby wrote, and then
// TLA-conn@90> \* our FIN, unless the connection ends or the peer is gone.
// TLA-conn@90> ToPeer == SF_s(PeerAcks) =>
// TLA-conn@90>             (s.phase = "open" /\ (s.p.fromRuby > 0 \/ s.k.tx > 0 \/ s.p.fromShut)
// TLA-conn@90>                ~> \/ s.p.fromRuby = 0 /\ s.k.tx = 0 /\ (~s.p.fromShut \/ s.k.up = "ended")
// TLA-conn@90>                   \/ s.phase # "open" \/ s.k.gone \/ s.k.cut)
// TLA-conn@90> \* CleanEof says that Ruby reads the end of the stream only when the peer
// TLA-conn@90> \* ended it. It does not hold: a reset ends the stream too. Ruby then
// TLA-conn@90> \* reads the end, or ECONNRESET if the pair still held bytes that it had
// TLA-conn@90> \* written.
// TLA-conn@90> CleanEof == s.told /\ s.p.gone = "no" => s.k.fin
//
// The buffers of the model hold a byte each, so each is either empty or
// full.
//
// TLA-conn.cfg> SPECIFICATION Spec
// TLA-conn.cfg> CONSTANTS Budget = 2
// TLA-conn.cfg>   TxCap = 1
// TLA-conn.cfg>   RxCap = 1
// TLA-conn.cfg>   PairCap = 1
// TLA-conn.cfg>   Fault = "none"
// TLA-conn.cfg> INVARIANTS RemovedClean DeadEnds NoneWithheld FinIsBare
// TLA-conn.cfg>   NoMissedWake NoSpin OpenIsGreeted SaidAtTheEnd
// TLA-conn.cfg> PROPERTIES SaidOnce Kept DeadGoes SilenceEnds LetGo NotBegun Answered ToRuby ToPeer
// TLA-conn.cfg> CHECK_DEADLOCK FALSE
//
// A pair that holds two bytes can be half full. poll then reports no room
// for a write that would find some.
//
// TLA-conn.cfg/half> PairCap = 2
//
// With room for two bytes in every buffer, and a third byte to write, the
// model is some four times as large, and TLC would take long over the
// properties that say what happens in the end. This variant checks the
// others.
//
// TLA-conn.cfg/roomy> Budget = 3
// TLA-conn.cfg/roomy> TxCap = 2
// TLA-conn.cfg/roomy> RxCap = 2
// TLA-conn.cfg/roomy> PairCap = 2
// TLA-conn.cfg/roomy> PROPERTIES SaidOnce Kept
//
// Each of these variants has a fault that the code avoids, and the model
// finds each. A socket is removed as soon as Ruby's part is over:
//
// TLA-conn.cfg/remove-at-once!RemovedClean> Fault = "remove at once"
//
// Ruby is sent the status before the handshake is over:
//
// TLA-conn.cfg/greets-early!OpenIsGreeted> Fault = "greets early"
//
// A socket that listened is kept when its handshake has failed:
//
// TLA-conn.cfg/keeps-a-failure!NotBegun> Fault = "keeps a failure"
//
// poll is not asked about a descriptor that is neither read nor written:
//
// TLA-conn.cfg/hangup-unwatched!NoMissedWake> Fault = "hangup unwatched"
//
// poll is asked about a hangup that it has already reported:
//
// TLA-conn.cfg/hangup-always-watched!NoSpin> Fault = "hangup always watched"
//
// poll is asked whether the pair takes bytes that it has refused, and it
// returns for them for ever:
//
// TLA-conn.cfg/deaf-asks!NoSpin> Fault = "deaf asks"
//
// poll is not asked whether Ruby has written, or whether the pair has
// room for what the peer sent:
//
// TLA-conn.cfg/reads-unasked!ToPeer> Fault = "reads unasked"
// TLA-conn.cfg/writes-unasked!ToRuby> Fault = "writes unasked"
//
// A connection that Ruby has left has no deadline but the one in
// FIN-WAIT-2:
//
// TLA-conn.cfg/no-deadline!LetGo> Fault = "no deadline"
//
// The socket does not ask a quiet peer to answer:
//
// TLA-conn.cfg/no-keep-alive!Kept> Fault = "no keep-alive"
//
// The socket forgets what it holds for Ruby once both streams have ended:
//
// TLA-conn.cfg/no-tail!Kept> Fault = "no tail"
//
// carry drops what the pair refuses:
//
// TLA-conn.cfg/drops!Kept> Fault = "drops"
//
// A connection is closed when both streams have ended, though Ruby has
// yet to be given the last bytes that the peer sent:
//
// TLA-conn.cfg/early-close!Kept> Fault = "early close"
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
    use std::os::fd::{FromRawFd, RawFd};
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
            let mut moved = false;
            a.turn();
            b.turn();
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
        a.turn();
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
        assert!(b.conns.len() == 1 && matches!(b.conns[0].phase, Phase::Open(_)) && b.listeners[0].unaccepted == 1);
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
        b.turn();
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
        assert!((SEND_BUF + RECV_BUF..END).contains(&at), "the writer waits after {at} bytes");
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

    /// Returns how many bytes the socket of a stack's one connection holds
    /// for Ruby.
    fn held(stack: &Stack) -> usize {
        stack.sockets.get::<tcp::Socket>(stack.conns[0].handle).recv_queue()
    }

    /// Changes the 16-bit word at a place in the TCP header of an IPv4
    /// packet, and corrects the checksum as RFC 1624 has it.
    fn set_word(packet: &mut [u8], at: usize, change: impl Fn(u16) -> u16) {
        let t = &mut packet[20..];
        let old = u16::from_be_bytes([t[at], t[at + 1]]);
        let new = change(old);
        let mut sum = u32::from(!u16::from_be_bytes([t[16], t[17]])) + u32::from(!old) + u32::from(new);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        t[at..at + 2].copy_from_slice(&new.to_be_bytes());
        t[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    fn put_fin(packet: &mut [u8]) {
        set_word(packet, 12, |flags| flags | 0x01);
    }

    fn set_window(packet: &mut [u8], window: u16) {
        set_word(packet, 14, |_| window);
    }

    /// Gives A what B has to send. Linux puts its FIN on the last segment
    /// of data that it has still to send when a program closes its end.
    /// This stack has smoltcp send its FIN apart, so the FIN is put on
    /// B's segments here. A segment of one byte is left as it is, because
    /// it may be a probe of A's window.
    fn give_with_a_fin(b: &mut Stack, a: &mut Stack) {
        while let Some(mut packet) = b.transmit() {
            // The headers of IP and of TCP are 40 bytes.
            if packet.len() > 41 {
                put_fin(&mut packet);
            }
            a.receive(packet);
        }
    }

    /// Returns what Ruby reads from A as far as the end of the stream,
    /// with a FIN on the segments of B that have data.
    fn read_to_a_fin(a: &mut Stack, b: &mut Stack, ruby: &mut UnixStream) -> Vec<u8> {
        let mut got = Vec::new();
        for _ in 0..100 {
            give_with_a_fin(b, a);
            a.turn();
            while let Some(packet) = a.transmit() {
                b.receive(packet);
            }
            b.turn();
            let (bytes, end) = read(ruby);
            got.extend(bytes);
            if end {
                return got;
            }
            std::thread::sleep(Duration::from_millis(12));
        }
        panic!("Ruby read {} bytes and no end of the stream", got.len());
    }

    #[test]
    fn a_stream_that_ends_where_the_window_ends_is_read_whole() {
        // The client's socket has this much room when the server writes
        // the last of its stream, which is two writes. A window that
        // smoltcp scaled would be all of the room before the first write,
        // which is a multiple of 8 bytes, and less than the room for the
        // second, which is an odd number of bytes.
        const ROOM: usize = 4096;
        const LAST: usize = 1001;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The client reads nothing. Its pair fills, and then its socket
        // begins to.
        let mut at = 0;
        while held(&a) == 0 {
            at = write_from(&mut server, at, at + 16384);
            settle(&mut a, &mut b);
        }
        // The stream ends where the socket is full.
        let end = at - held(&a) + RECV_BUF;
        while at < end - ROOM {
            at = write_from(&mut server, at, end - ROOM);
            settle(&mut a, &mut b);
        }
        assert_eq!(held(&a), RECV_BUF - ROOM);
        // Both writes leave B before A has answered the first.
        at = write_from(&mut server, at, end - LAST);
        b.turn();
        while let Some(packet) = b.transmit() {
            a.receive(packet);
        }
        assert_eq!(write_from(&mut server, at, end), end);
        b.turn();
        // A acknowledges the first write at once, as it is more than a
        // segment, and the window that it tells of is all of the room.
        // With a scaled window it would be a byte short of the second
        // write, and smoltcp would drop the last byte of the stream.
        a.turn();
        // The second write is all that B has left to send, and A takes the
        // whole of it.
        give_with_a_fin(&mut b, &mut a);
        a.turn();
        assert_eq!(held(&a), RECV_BUF);
        let got = read_to_a_fin(&mut a, &mut b, &mut client);
        assert_eq!(got.len(), end);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    #[test]
    fn a_fin_is_not_taken_with_a_segment_that_the_window_cut() {
        // The client's socket has room for this much of the last write.
        const ROOM: usize = 500;
        const LAST: usize = 1001;
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The client reads nothing. Its pair fills, and then its socket
        // does, but for the room.
        let mut at = 0;
        while held(&a) == 0 {
            at = write_from(&mut server, at, at + 16384);
            settle(&mut a, &mut b);
        }
        let end = at - held(&a) + RECV_BUF - ROOM + LAST;
        while at < end - LAST {
            at = write_from(&mut server, at, end - LAST);
            settle(&mut a, &mut b);
        }
        assert_eq!(held(&a), RECV_BUF - ROOM);
        // A segment from A tells B of more room than A has on record, as a
        // keep-alive may when Ruby has read a little since the last ACK.
        client.write_all(b"x").unwrap();
        a.turn();
        let mut packet = a.transmit().unwrap();
        set_window(&mut packet, 2 * LAST as u16);
        b.receive(packet);
        b.turn();
        // So B sends the whole of the last write, and A takes the part of
        // it that there is room for.
        assert_eq!(write_from(&mut server, at, end), end);
        b.turn();
        give_with_a_fin(&mut b, &mut a);
        a.turn();
        assert_eq!(held(&a), RECV_BUF);
        // B sends the rest again when Ruby has read.
        let got = read_to_a_fin(&mut a, &mut b, &mut client);
        assert_eq!(got.len(), end);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    #[test]
    fn a_peer_that_has_filled_a_shut_window_is_still_heard() {
        // The server fills the client's socket with the two writes of the
        // test above, and the client reads nothing.
        const ROOM: usize = 4096;
        const LAST: usize = 1001;
        let (mut a, mut b) = (stack(A), stack(B));
        let (_client, mut server) = connected(&mut a, &mut b);
        let mut at = 0;
        while held(&a) == 0 {
            at = write_from(&mut server, at, at + 16384);
            settle(&mut a, &mut b);
        }
        let end = at - held(&a) + RECV_BUF;
        while at < end - ROOM {
            at = write_from(&mut server, at, end - ROOM);
            settle(&mut a, &mut b);
        }
        at = write_from(&mut server, at, end - LAST);
        b.turn();
        while let Some(packet) = b.transmit() {
            a.receive(packet);
        }
        assert_eq!(write_from(&mut server, at, end), end);
        b.turn();
        a.turn();
        // `top` is the sequence number after the last byte that B sends.
        let mut top = 0;
        while let Some(packet) = b.transmit() {
            let seq = u32::from_be_bytes(packet[24..28].try_into().unwrap());
            top = seq.wrapping_add(packet.len() as u32 - 40);
            a.receive(packet);
        }
        a.turn();
        // A's timers run 150 times as fast: its timeout is two seconds,
        // and it asks B to answer every half second.
        let s = a.sockets.get_mut::<tcp::Socket>(a.conns[0].handle);
        s.set_timeout(s.timeout().map(|timeout| timeout / 150));
        let interval = s.keep_alive().map(|interval| interval / 150);
        s.set_keep_alive(None);
        s.set_keep_alive(interval);
        // B answers with an ACK that has no data. Linux numbers such an
        // ACK from the last byte that it has sent, and B's ACK is given
        // that number here. With a scaled window that byte would be past
        // the end of A's window, and A would not count the answer.
        let begun = a.clock;
        while a.clock - begun < Duration::from_secs(4) {
            a.turn();
            while let Some(packet) = a.transmit() {
                assert!(!is_reset(&packet), "A resets a peer that answers");
                b.receive(packet);
            }
            b.turn();
            while let Some(mut packet) = b.transmit() {
                if packet.len() == 40 {
                    set_word(&mut packet, 4, |_| (top >> 16) as u16);
                    set_word(&mut packet, 6, |_| top as u16);
                }
                a.receive(packet);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(a.sockets.get::<tcp::Socket>(a.conns[0].handle).state(), tcp::State::Established);
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
    fn a_write_fails_once_the_peer_has_reset() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The server reads nothing, so its pair fills, and then its socket.
        let (mut at, mut before) = (0, usize::MAX);
        while at != before {
            before = at;
            at = write_from(&mut client, at, 1 << 20);
            settle(&mut a, &mut b);
        }
        a.sockets.get_mut::<tcp::Socket>(a.conns[0].handle).abort();
        settle(&mut a, &mut b);
        assert!(b.conns.len() == 1 && held(&b) > 0, "B has bytes that the server can still read");
        assert_eq!(server.write(b"more").unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        let mut got = Vec::new();
        loop {
            let (bytes, ended) = read(&mut server);
            got.extend(bytes);
            if ended {
                break;
            }
            settle(&mut a, &mut b);
        }
        assert!(!got.is_empty() && got.iter().enumerate().all(|(i, b)| *b == byte(i)));
        settle(&mut a, &mut b);
        assert!(b.conns.is_empty());
    }

    #[test]
    fn an_end_closed_with_bytes_unread_resets_though_its_pair_is_not_read() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // The server reads nothing. So A's socket fills, and A reads the
        // client's pair no more.
        let (mut at, mut before) = (0, usize::MAX);
        while at != before {
            before = at;
            at = write_from(&mut client, at, 1 << 20);
            settle(&mut a, &mut b);
        }
        server.write_all(b"unread").unwrap();
        settle(&mut a, &mut b);
        drop(client);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty(), "A finds the bytes unread without a read of the pair");
        assert_eq!(server.write(b"more").unwrap_err().kind(), std::io::ErrorKind::BrokenPipe, "and B was reset");
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
        const END: usize = 500 << 10;
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
        // The server can still read what reached it, and then the end. That
        // is what its pair holds, and what its socket holds after the
        // reset.
        let in_socket = held(&b);
        let (in_pair, _) = read(&mut server);
        let mut got = in_pair.len();
        for _ in 0..100 {
            settle(&mut a, &mut b);
            let (bytes, end) = read(&mut server);
            got += bytes.len();
            if end {
                break;
            }
        }
        assert!(in_socket > 0 && got == in_pair.len() + in_socket && got < END, "{got} bytes arrived");
        assert!(b.conns.is_empty());
    }

    #[test]
    fn the_peer_has_its_time_from_when_it_has_taken_everything() {
        const END: usize = 500 << 10;
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
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert_eq!(b.conns.len(), 1);
        b.receive(syn);
        b.turn();
        assert!(b.conns.len() == 1 && b.transmit().is_none(), "the second copy is passed over");
        a.receive(answer);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert!(b.conns.len() == 1 && matches!(b.conns[0].phase, Phase::Open(_)));
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
        a.turn();
        let reset = a.transmit().unwrap();
        assert!(is_reset(&reset));
        b.receive(reset);
        b.receive(syn);
        b.turn();
        assert!(b.conns.len() == 1 && b.transmit().is_none(), "the second copy is passed over");
        a.receive(answer);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::OK], false));
        assert!(b.conns.len() == 1 && matches!(b.conns[0].phase, Phase::Open(_)));
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
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        // Ruby ends its writing. The peer answers with more than the pair
        // holds, so the socket holds the rest, and ends too.
        client.shutdown(Shutdown::Write).unwrap();
        let mut at = 0;
        while held(&a) == 0 {
            at = write_from(&mut server, at, at + 16384);
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
        assert_eq!(got.len(), at);
        assert!(got.iter().enumerate().all(|(at, got)| *got == byte(at)));
    }

    #[test]
    fn a_fin_waits_for_a_peer_that_ended_first_to_take_the_data() {
        const END: usize = 500 << 10;
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
                set_window(&mut packet, 0);
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
        assert!(client.write_all(b"too late").is_err(), "the pair takes no more from Ruby");
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
        a.turn();
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
        // A peer such as Linux may put its FIN on its last segment of
        // data. This stack has smoltcp send its FIN apart, so the FIN is
        // put on B's segment here.
        let mut last = b.transmit().unwrap();
        put_fin(&mut last);
        a.receive(last);
        a.turn();
        assert!(matches!(a.conns[0].phase, Phase::Dead { .. }) && a.transmit().is_none(), "the ACK is delayed");
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
        assert!(
            matches!(&a.conns[..], [Conn { phase: Phase::Open(open), .. }] if open.pair.deaf()) && b.conns.len() == 1
        );
        assert_eq!(held(&a), b"unheard".len(), "the socket keeps what the pair refused");
        // The end leaves bytes that it did not take, and the peer is told.
        drop(client);
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty() && b.conns.is_empty());
        assert!(server.write_all(b"anyone?").is_err(), "the peer was reset");
    }
}

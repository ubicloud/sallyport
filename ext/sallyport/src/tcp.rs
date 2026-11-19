//! The TCP side of a tunnel is smoltcp's stack and, for each connection,
//! a Unix socket pair. Ruby holds one end of the pair, which is a
//! descriptor that it can select on and give to OpenSSL. The stack holds
//! the other end, and moves bytes between it and the buffers of the TCP
//! socket. The buffers of both are bounded, so each direction has flow
//! control from end to end.
//!
//! This file has the stack: the packets, the listeners, and the loop that
//! turns each connection. conn.rs has what one connection does in a turn.

use crate::config::Config;
use crate::conn::{status, step, Open, Phase};
use crate::ctl::Ctl;
use crate::packet::{ends, rst, split_fin, syn, without_sack};
use crate::pair::{Pair, PairCalls};
use crate::sock::{Sock, Socket};
use crate::sys;
use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// The stack's clock goes on by no more than this from one reading to the
/// next. The tunnel's thread reads it several times a second, so a longer
/// time is one in which the thread stood still.
const STEP: Duration = Duration::from_secs(1);
/// The loop passes over every connection this often, whatever has
/// happened to it. That is when the times of a connection are looked
/// at, and when the loop finds what a timer of smoltcp did to a socket.
const CHECK: Duration = Duration::from_millis(250);
/// The epoll set names a pair by the number of its listener with this
/// bit, or by the number of its connection.
const LISTENER: u64 = 1 << 63;
/// One turn of the loop has the sockets send this many rounds of packets
/// at the most, with a packet from each socket in a round.
const EGRESS_ROUNDS: usize = 1024;
/// An outbound connection takes one of this many local ports, of which
/// this is the first. They are the ports that IANA leaves for the purpose.
const FIRST_PORT: u16 = 49152;
const PORTS: u16 = 16384;

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

/// A connection has a socket of smoltcp, and is in a phase as conn.rs
/// has it.
struct Conn {
    /// `id` is a number that no other connection of the stack has had.
    /// The connections are kept in the order of their numbers.
    id: u64,
    handle: SocketHandle,
    /// The local port that an outbound connection took.
    local_port: Option<u16>,
    phase: Phase,
    /// Something has happened to the connection since its last pass, so
    /// that a pass may find something to do.
    cause: bool,
    /// The descriptor of the connection's pair that the epoll set
    /// holds, with the events that it watches for.
    watched: Option<(RawFd, libc::c_short)>,
}

// The model "conn" is in conn.rs. Some of its lines are in this file,
// beside what the loop does for each connection: in poll, turn, orphan,
// abort and sweep.

/// A SYN to a port meets one of these.
enum Welcome {
    /// Nothing listens on the port, and smoltcp resets the SYN.
    Nobody,
    /// The listener has no room for another connection.
    Full,
    /// The listener made a socket for the SYN.
    Socket,
}

// The model "listen" is of one listener: the sockets that are made for
// the SYNs to its port, the peers that send them, and what Ruby has yet to
// accept. The lines of the model are beside the code that they describe,
// and Ruby's part is in listener.rb.
//
// TLA-listen@0> EXTENDS Naturals
// TLA-listen@0> CONSTANTS Peers,    \* each peer sends SYNs to the port from one address and port
// TLA-listen@0>           Backlog,  \* how many connections the listener lets wait
// TLA-listen@0>           Holds,    \* how many connections the listener's pair holds for Ruby
// TLA-listen@0>           Fault     \* the fault that a variant puts in, or "none"
// TLA-listen@0> \* The listener's pair is the one that ctl.rs describes.
// TLA-listen@0> C == INSTANCE ctl
// TLA-listen@0> \* The state is one record, so that a step says what it changes and no more.
// TLA-listen@0> VARIABLE s
// TLA-listen@0> Init == s = [
// TLA-listen@0>   c          |-> C!New,  \* Listener.ctl
// TLA-listen@0>   listening  |-> 0,      \* the sockets that listen, and have no connection yet
// TLA-listen@0>   shaking    |-> [p \in Peers |-> 0],      \* the sockets that have answered a SYN of the peer
// TLA-listen@0>   made       |-> [p \in Peers |-> 0],      \* its connections that Ruby has yet to be sent
// TLA-listen@0>   given      |-> [p \in Peers |-> 0],      \* those that Ruby was sent
// TLA-listen@0>   refused    |-> [p \in Peers |-> FALSE]]  \* a SYN of the peer was reset
// TLA-listen@0> When(cond, x) == IF cond THEN {x} ELSE {}
// TLA-listen@0> RECURSIVE Sum(_, _)
// TLA-listen@0> Sum(f, S) == IF S = {} THEN 0 ELSE LET p == CHOOSE p \in S : TRUE IN f[p] + Sum(f, S \ {p})
// TLA-listen@0> \* The connections that wait for the listener are those of Phase::Listening.
// TLA-listen@0> Waiting(t) == t.listening + Sum(t.shaking, Peers) + Sum(t.made, Peers)

struct Listener {
    /// A connection that waits for its listener names it by this, so that
    /// it is not taken for a connection of a later listener on the port.
    id: u64,
    port: u16,
    /// Our end of the pair on which Ruby is sent each connection.
    ctl: Ctl,
    backlog: usize,
    /// Ruby has answered on the pair or closed it, or it is time to
    /// look.
    cause: bool,
}

pub struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    link: Link,
    conns: Vec<Conn>,
    listeners: Vec<Listener>,
    /// How many listeners there have been, and how many connections.
    listened: u64,
    made: u64,
    /// The epoll set that holds the pairs of the connections and of the
    /// listeners, and room for the names that it reports.
    set: OwnedFd,
    names: Vec<u64>,
    /// When the loop last passed over every connection.
    checked: Duration,
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

impl Stack {
    /// Makes a stack that keeps its descriptors in `set`, which is an
    /// epoll set that sys::epoll made.
    pub fn new(cfg: &Config, sack: bool, set: OwnedFd) -> Stack {
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
            made: 0,
            set,
            names: Vec::new(),
            checked: Duration::ZERO,
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
        Pair::new(fd).say(code);
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
        let Some(s) = Sock::connecting(self.iface.context(), addr, port, local) else {
            self.local_ports.remove(&local);
            return Stack::refuse(fd, status::NO_ROUTE);
        };
        let handle = self.sockets.add(s);
        let phase = Phase::Connecting { pair: Pair::new(fd), since: self.clock };
        self.add(handle, Some(local), phase);
    }

    /// Adds a connection, which has cause for its first pass.
    fn add(&mut self, handle: SocketHandle, local_port: Option<u16>, phase: Phase) {
        self.made += 1;
        self.conns.push(Conn { id: self.made, handle, local_port, phase, cause: true, watched: None });
    }

    /// Listens on a TCP port. `ctl` is our end of the pair on which Ruby
    /// is told whether the port was free, and is then sent each
    /// connection.
    pub fn listen(&mut self, ctl: OwnedFd, port: u16, backlog: usize) {
        // Ruby may have closed a listener on this port a moment ago.
        self.reap();
        let ctl = Ctl::new(ctl);
        // Ruby reads the status, or the end of the pair if the status
        // could not be sent. So a listener that Ruby cannot be told of is
        // not kept.
        let free = !self.listeners.iter().any(|l| l.port == port);
        if ctl.say(if free { status::OK } else { status::IN_USE }) && free {
            self.listened += 1;
            // The pair is watched for Ruby accepting a connection and for
            // Ruby closing the listener.
            sys::watch(self.set.as_raw_fd(), ctl.raw(), libc::POLLIN, LISTENER | self.listened, false);
            self.listeners.push(Listener { id: self.listened, port, ctl, backlog, cause: false });
        }
    }

    /// Stops the listening on each port whose listener Ruby has closed. A
    /// connection that Ruby was not sent then finds no listener, and is
    /// reset at its next step.
    fn reap(&mut self) {
        self.listeners.retain(|l| !l.ctl.ended());
    }

    // TLA-listen> \* welcome and pump have the pair count the answers that Ruby has sent.
    // TLA-listen> Credit(t) == IF Fault = "uncounted" THEN t ELSE [t EXCEPT !.c = C!Credited(@)]
    // TLA-listen> \* welcome says one of these for a SYN whose connection no socket has. A
    // TLA-listen> \* listener has room until the connections that Ruby has not accepted, and
    // TLA-listen> \* those that wait for the listener, are as many as its backlog.
    // TLA-listen> Welcome(t) == LET waiting == IF Fault = "counts no handshakes" THEN 0 ELSE Waiting(t)
    // TLA-listen>               IN IF C!Ended(t.c) THEN "nobody"
    // TLA-listen>                  ELSE IF Credit(t).c.unaccepted + waiting >= Backlog THEN "full"
    // TLA-listen>                  ELSE "socket"
    /// Makes a socket for a SYN to a port, if the port is listened on and
    /// its listener has room. A listener has room until the connections
    /// that Ruby has not accepted, and the handshakes under way, are as
    /// many as its backlog. smoltcp keeps no queue of them: a socket takes
    /// one connection.
    fn welcome(&mut self, port: u16) -> Welcome {
        let Some(l) = self.listeners.iter_mut().find(|l| l.port == port) else { return Welcome::Nobody };
        // Ruby may have closed the listener a moment ago.
        if l.ctl.ended() {
            return Welcome::Nobody;
        }
        l.ctl.credit();
        let waits = |c: &&Conn| matches!(c.phase, Phase::Listening { listener, .. } if listener == l.id);
        let pending = l.ctl.unaccepted() + self.conns.iter().filter(waits).count();
        if pending >= l.backlog {
            return Welcome::Full;
        }
        let Some(s) = Sock::listening(port) else { return Welcome::Full };
        let handle = self.sockets.add(s);
        let phase = Phase::Listening { listener: l.id, since: self.clock };
        self.add(handle, None, phase);
        Welcome::Socket
    }

    // TLA-listen> \* Stack::has
    // TLA-listen> Has(t, p) == t.shaking[p] + t.made[p] + t.given[p] > 0
    /// Says whether a socket already has the connection between these two
    /// ends.
    fn has(&self, from: SocketAddr, to: SocketAddr) -> bool {
        self.conns.iter().any(|c| Sock::has(self.sockets.get::<Socket>(c.handle), from, to))
    }

    // TLA-listen> \* smoltcp gives a SYN to the first socket that will take it. A socket
    // TLA-listen> \* that has the peer's connection takes the SYN, and stays as it is. A
    // TLA-listen> \* socket that listens takes any SYN. The model does not say which socket
    // TLA-listen> \* is the first. smoltcp resets a SYN that no socket takes.
    // TLA-listen> Takes(u, p) == When(Has(u, p), u)
    // TLA-listen>           \cup When(u.listening > 0, [u EXCEPT !.listening = @ - 1, !.shaking[p] = @ + 1])
    // TLA-listen> Smoltcp(u, p) == IF Takes(u, p) = {} THEN {[u EXCEPT !.refused[p] = TRUE]} ELSE Takes(u, p)
    // TLA-listen> \* A SYN arrives. If no socket has its connection, ingress asks welcome,
    // TLA-listen> \* which makes a socket for it or has it dropped. smoltcp gives a good SYN
    // TLA-listen> \* to a socket, and gives one that is for no address of the tunnel to
    // TLA-listen> \* none. ingress then removes each socket that still listens.
    // TLA-listen> Syn(p, good) ==
    // TLA-listen>   LET fresh == ~Has(s, p) \/ Fault = "takes twice"
    // TLA-listen>       w == IF fresh THEN Welcome(s) ELSE "none"
    // TLA-listen>       t == IF fresh /\ s.c.open THEN Credit(s) ELSE s
    // TLA-listen>       u == IF w = "socket" THEN [t EXCEPT !.listening = @ + 1] ELSE t
    // TLA-listen>   IN IF w = "full" /\ Fault # "resets when full" THEN s' = t
    // TLA-listen>      ELSE \E v \in (IF good THEN Smoltcp(u, p) ELSE {u}) :
    // TLA-listen>             s' = IF w = "socket" /\ Fault # "keeps its socket" THEN Unlisten(v) ELSE v
    // TLA-listen> \* A reset arrives. smoltcp does not close a socket that had answered the
    // TLA-listen> \* peer's SYN: it has the socket listen again, and ingress removes it. An
    // TLA-listen> \* established connection that Ruby was not sent is closed, and step
    // TLA-listen> \* removes it.
    // TLA-listen> Rst(p) == \E v \in When(s.shaking[p] > 0, [s EXCEPT !.shaking[p] = @ - 1, !.listening = @ + 1])
    // TLA-listen>                    \cup When(s.made[p] > 0, [s EXCEPT !.made[p] = @ - 1])
    // TLA-listen>                    \cup When(s.given[p] > 0 \/ ~Has(s, p), s) :
    // TLA-listen>             s' = IF Fault = "keeps listeners" THEN v ELSE Unlisten(v)
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
            // The connection that the packet is for has cause for a
            // pass. It is found before smoltcp has the packet: a socket
            // that is reset has its ends no more. A packet that this
            // file cannot read is one that smoltcp gives to no socket.
            if let Some((from, to)) = ends(packet) {
                let sockets = &self.sockets;
                let theirs = |c: &&mut Conn| Sock::has(sockets.get::<Socket>(c.handle), from, to);
                if let Some(c) = self.conns.iter_mut().find(theirs) {
                    c.cause = true;
                }
            }
            let made = match fresh.map(|(_, to)| self.welcome(to.port())) {
                // smoltcp would reset a SYN that finds no socket, and its
                // sender would take that to mean that nothing listens. A
                // SYN that the backlog has no room for is dropped, as
                // Linux drops it, and its sender tries again.
                Some(Welcome::Full) => {
                    self.link.rx.pop_front();
                    continue;
                }
                Some(Welcome::Socket) => true,
                Some(Welcome::Nobody) | None => false,
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
            if made || reset {
                self.unlisten();
            }
        }
    }

    // TLA-listen@40> Unlisten(u) == [u EXCEPT !.listening = 0]
    /// Removes each socket that listens, and its connection.
    fn unlisten(&mut self) {
        let sockets = &mut self.sockets;
        self.conns.retain(|c| {
            let listens = matches!(c.phase, Phase::Listening { .. }) && Sock::listens(sockets.get::<Socket>(c.handle));
            if listens {
                sockets.remove(c.handle);
            }
            !listens
        });
    }

    // TLA-listen@60> \* The peer finishes the handshake, or step gives the handshake up when
    // TLA-listen@60> \* it is SYN_WAIT old.
    // TLA-listen@60> Ack(p) == s.shaking[p] > 0 /\ s' = [s EXCEPT !.shaking[p] = @ - 1, !.made[p] = @ + 1]
    // TLA-listen@60> GivesUp(p) == s.shaking[p] > 0 /\ s' = [s EXCEPT !.shaking[p] = @ - 1]
    // TLA-listen@60> \* step sends Ruby a connection that is established, and counts it. A
    // TLA-listen@60> \* connection that finds the pair full waits for a later turn. step
    // TLA-listen@60> \* resets what waits for a listener that Ruby has closed.
    // TLA-listen@60> Hand(p) == \/ /\ s.c.open /\ s.made[p] > 0 /\ ~C!Full(s.c)
    // TLA-listen@60>               /\ s' = [s EXCEPT !.made[p] = @ - 1, !.given[p] = @ + 1, !.c = C!Sent(@)]
    // TLA-listen@60>            \/ ~s.c.open /\ s.made[p] > 0 /\ s' = [s EXCEPT !.made[p] = @ - 1]
    // TLA-listen@60>            \/ ~s.c.open /\ s.shaking[p] > 0 /\ s' = [s EXCEPT !.shaking[p] = @ - 1]
    // TLA-listen@60> \* A connection that Ruby was sent ends, and its socket goes.
    // TLA-listen@60> Ends(p) == s.given[p] > 0 /\ s' = [s EXCEPT !.given[p] = @ - 1]
    // TLA-listen@60> \* pump counts Ruby's answers at each turn.
    // TLA-listen@60> Counts == s.c.open /\ s.c.answers > 0 /\ Credit(s) # s /\ s' = Credit(s)
    // TLA-listen@60> \* Ruby accepts a connection when it likes, and may close the listener at
    // TLA-listen@60> \* any time.
    // TLA-listen@60> Accept == \E c \in C!Accepts(s.c) : s' = [s EXCEPT !.c = c]
    // TLA-listen@60> Close == \E c \in C!Closes(s.c) : s' = [s EXCEPT !.c = c]

    /// Returns how many connections there are: those that the stack is
    /// making, and those that are made and have not ended.
    pub fn connections(&self) -> usize {
        self.conns.iter().filter(|c| !matches!(c.phase, Phase::Listening { .. } | Phase::Dead)).count()
    }

    /// Describes every connection in a line, which is what the stack
    /// knows of it. With `detail`, a second line is smoltcp's account of
    /// the socket. That one takes milliseconds to write for each
    /// connection, because smoltcp writes out every byte of the socket's
    /// buffers on the way, and the thread does nothing else meanwhile.
    pub fn describe(&self, text: &mut String, detail: bool) {
        for c in &self.conns {
            let (phase, pair) = match &c.phase {
                Phase::Connecting { pair, .. } => ("connecting", Some(pair)),
                Phase::Listening { .. } => ("listening", None),
                Phase::Open(open) => ("open", Some(&open.pair)),
                Phase::Dead => ("dead", None),
            };
            let (tail, left) = match &c.phase {
                Phase::Open(open) => (open.tail.len(), open.left.is_some()),
                _ => (0, false),
            };
            let s = self.sockets.get::<Socket>(c.handle);
            let _ = writeln!(
                text,
                "{phase} {}, {} waiting in the pair{}{}{}",
                Sock::describe(s, tail),
                pair.map_or(0, Pair::waiting),
                if pair.is_some_and(Pair::done) { ", no more comes from Ruby" } else { "" },
                if pair.is_some_and(Pair::told) { ", the peer has ended its stream" } else { "" },
                if left { ", Ruby is gone" } else { "" },
            );
            if detail {
                let _ = writeln!(text, "  {}", Sock::detail(s));
            }
        }
    }

    // TLA-conn> \* Every turn of the loop has each socket send what it owes.
    // TLA-conn> Dispatch == s.phase # "removed" /\ K!Owes(s.k) /\ s' = [s EXCEPT !.k = K!Sent(@)]
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

    // TLA-conn@70> \* A turn makes a pass over this connection when something has happened
    // TLA-conn@70> \* to it: a packet, a time of its own, or what poll would report of its
    // TLA-conn@70> \* pair. That is Wake. The loop also passes over every connection four
    // TLA-conn@70> \* times a second, whatever has happened, and Turn is that pass.
    // TLA-conn@70> Turn == s.at = "idle" /\ s.phase \in Live /\ s' = [s EXCEPT !.at = First(s), !.kick = FALSE]
    // TLA-conn@70> Wake == (s.kick \/ FdReady(s)) /\ Turn
    // TLA-conn@70> Step == s.at # "idle" /\ s' = StepAt(s)
    /// Takes in the packets that arrived, moves on each connection that
    /// has cause, has every socket send what it has to send, and removes
    /// the connections that owe the peer nothing more. So an ACK tells
    /// the peer of the room that there is once Ruby has been given its
    /// bytes, and what Ruby wrote leaves in the turn that took it.
    ///
    /// A connection has cause for a pass when a packet arrived for it,
    /// when the epoll set reports its pair or the pair of the listener
    /// that it waits for, and four times a second. A pass over any other
    /// connection would change nothing, as NoMissedWake says in the
    /// model, and it would cost a read and a poll.
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
        // A dead connection's socket owes the peer one packet at the most,
        // a reset or the ACK of the peer's FIN, and it delays neither. So
        // the first round has sent that packet, and the socket goes now,
        // whatever the other sockets have left to send
        // (`a_connection_that_ends_goes_though_another_has_more_to_send`).
        self.sweep();
    }

    // TLA-conn> \* The tunnel is closing. orphan shuts down each pair both ways, and
    // TLA-conn> \* leaves no listener. The loop turns at once.
    // TLA-conn> Orphan == /\ s.at = "idle" /\ ~s.closing /\ s.phase # "removed"
    // TLA-conn>           /\ s' = [s EXCEPT !.closing = TRUE, !.kick = TRUE,
    // TLA-conn>                             !.listens = @ /\ s.phase # "listening",
    // TLA-conn>                             !.p = IF s.phase \in {"connecting", "open"} /\ Fault # "closes quietly"
    // TLA-conn>                                   THEN P!Shut(@) ELSE @]
    /// Stops the listening, and leaves every connection as it would be if
    /// Ruby had closed its end. The tunnel is closing.
    pub fn orphan(&mut self) {
        // A connection that Ruby was not sent finds no listener, and is
        // reset at its next step.
        self.listeners.clear();
        self.closing = true;
        for c in &mut self.conns {
            c.cause = true;
            // To our end, the pair is then what a pair is whose other
            // end Ruby has closed.
            if let Phase::Connecting { pair, .. } | Phase::Open(Open { pair, .. }) = &c.phase {
                pair.shut();
            }
        }
    }

    /// Says whether every connection has ended, and its socket has sent
    /// what it owed.
    pub fn finished(&self) -> bool {
        self.conns.is_empty()
    }

    // TLA-conn> \* The linger is over. abort resets a connection that has not ended. The
    // TLA-conn> \* poll that follows sends what every socket owes, and the thread ends.
    // TLA-conn> Finish == /\ s.at = "idle" /\ s.closing /\ s.phase # "removed"
    // TLA-conn>           /\ LET k == IF s.phase = "dead" THEN s.k ELSE K!Abort(s.k)
    // TLA-conn>              IN s' = [s EXCEPT !.phase = "removed", !.k = K!Sent(k)]
    /// Resets every connection that has not ended. The resets leave at
    /// the next poll.
    pub fn abort(&mut self) {
        for c in self.conns.iter().filter(|c| !matches!(c.phase, Phase::Dead)) {
            Sock::abort(self.sockets.get_mut::<Socket>(c.handle));
        }
    }

    /// Returns how long the stack can wait before its next timer.
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let now = self.now();
        self.iface.poll_delay(now, &self.sockets).map(|d| Duration::from_micros(d.total_micros()))
    }

    /// Marks what has cause for a pass, beyond what the packets gave.
    /// That is each pair that the epoll set reports, and everything when
    /// it is time to look at everything.
    fn stir(&mut self) {
        sys::ready(self.set.as_raw_fd(), &mut self.names, self.conns.len() + self.listeners.len());
        for name in &self.names {
            if name & LISTENER != 0 {
                if let Some(l) = self.listeners.iter_mut().find(|l| l.id == name & !LISTENER) {
                    l.cause = true;
                }
            } else if let Ok(at) = self.conns.binary_search_by_key(name, |c| c.id) {
                self.conns[at].cause = true;
            }
        }
        if self.clock.saturating_sub(self.checked) >= CHECK {
            self.checked = self.clock;
            self.listeners.iter_mut().for_each(|l| l.cause = true);
            self.conns.iter_mut().for_each(|c| c.cause = true);
        }
    }

    /// Moves each connection that has cause as far as it will go.
    fn pump(&mut self) {
        self.stir();
        // Ruby may have accepted connections, or closed a listener. A
        // connection that waits for that listener is stepped after it,
        // and has cause: there may be room for it now, or nobody to take
        // it.
        let mut stirred = Vec::new();
        for l in self.listeners.iter_mut().filter(|l| l.cause) {
            l.cause = false;
            l.ctl.credit();
            stirred.push(l.id);
        }
        if !stirred.is_empty() {
            self.listeners.retain(|l| !(stirred.contains(&l.id) && l.ctl.ended()));
            for c in &mut self.conns {
                c.cause |= matches!(c.phase, Phase::Listening { listener, .. } if stirred.contains(&listener));
            }
        }
        let set = self.set.as_raw_fd();
        for c in self.conns.iter_mut().filter(|c| c.cause) {
            c.cause = false;
            let s = self.sockets.get_mut::<Socket>(c.handle);
            // The step takes the phase, and gives back the phase to go on
            // in.
            let phase = std::mem::replace(&mut c.phase, Phase::Dead);
            // A connection that a peer made goes to Ruby on the pair of
            // its listener, unless Ruby has closed that listener.
            let ctl = match phase {
                Phase::Listening { listener, .. } => {
                    self.listeners.iter_mut().find(|l| l.id == listener).map(|l| &mut l.ctl)
                }
                _ => None,
            };
            c.phase = step(phase, s, ctl, self.clock, self.closing);
            // The set is told what to watch the pair for from now on. A
            // pair that is closed has left the set by itself.
            let watch = c.phase.watch(s).map(|p| (p.fd, p.events));
            match (c.watched, watch) {
                (was, now) if was == now => {}
                (was, Some((fd, events))) => sys::watch(set, fd, events, c.id, was.is_some_and(|(old, _)| old == fd)),
                (Some((fd, _)), None) if !matches!(c.phase, Phase::Dead) => sys::unwatch(set, fd),
                _ => {}
            }
            c.watched = watch;
        }
    }

    // TLA-conn> \* sweep removes a dead connection when its socket has sent what it owed.
    // TLA-conn> \* It does not wait for what the other sockets have to send.
    // TLA-conn> Sweep == /\ s.phase = "dead" /\ ~K!Owes(s.k) /\ Fault # "waits for the others"
    // TLA-conn>          /\ s' = [s EXCEPT !.phase = "removed"]
    /// Removes each dead connection whose socket owes the peer nothing.
    /// The socket has just sent the packet that it owed, if it owed one,
    /// so the socket of a connection that ended in this turn goes in this
    /// turn (`a_dead_connection_stays_until_its_socket_owes_nothing`).
    fn sweep(&mut self) {
        let (sockets, ports, cx) = (&mut self.sockets, &mut self.local_ports, self.iface.context());
        self.conns.retain(|c| {
            if !matches!(c.phase, Phase::Dead) || Sock::owes(sockets.get::<Socket>(c.handle), cx) {
                return true;
            }
            sockets.remove(c.handle);
            if let Some(port) = c.local_port {
                ports.remove(&port);
            }
            false
        });
    }

    /// Returns the descriptor that poll should watch for the
    /// connections and the listeners. It is the epoll set, which poll
    /// reports as readable while a pair in it has an event.
    pub fn poll_fd(&self) -> RawFd {
        self.set.as_raw_fd()
    }
}

// The model "listen" has two peers, and a backlog of one connection.
//
// TLA-listen@90> Next == \/ \E p \in Peers : Syn(p, TRUE) \/ Syn(p, FALSE) \/ Rst(p) \/ Ack(p) \/ GivesUp(p)
// TLA-listen@90>         \/ \E p \in Peers : Hand(p) \/ Ends(p)
// TLA-listen@90>         \/ Accept \/ Counts \/ Close
// TLA-listen@90> \* The stack counts and steps when it can, and gives up each handshake
// TLA-listen@90> \* that its peer leaves. The peers and Ruby owe nothing.
// TLA-listen@90> Spec == Init /\ [][Next]_s /\ WF_s(Counts) /\ \A p \in Peers : WF_s(Hand(p)) /\ WF_s(GivesUp(p))
// TLA-listen@90>
// TLA-listen@90> \* No more than the backlog are pending: the connections that Ruby has not
// TLA-listen@90> \* accepted, and those that wait for the listener.
// TLA-listen@90> Bounded == s.c.unaccepted + Waiting(s) <= Backlog
// TLA-listen@90> \* The listener's count is of the connections that Ruby has yet to take,
// TLA-listen@90> \* and of those that it has taken and credit has yet to count.
// TLA-listen@90> Exact == s.c.unaccepted = s.c.queued + s.c.answers
// TLA-listen@90> \* The pair has no more to hold each way than the backlog. Where it
// TLA-listen@90> \* holds as many, no connection waits for room in it. ctl.rs shows that
// TLA-listen@90> \* of a pair with the buffer that Linux gives one by default.
// TLA-listen@90> Fits == s.c.queued <= Backlog /\ s.c.answers <= Backlog
// TLA-listen@90> \* No socket listens between two packets. One that did would take the
// TLA-listen@90> \* next SYN to the port, whatever connection that SYN belonged to.
// TLA-listen@90> NoStray == s.listening = 0
// TLA-listen@90> \* A peer has one socket for its connection, however often its SYN arrives.
// TLA-listen@90> OnePerPeer == \A p \in Peers : s.shaking[p] + s.made[p] + s.given[p] <= 1
// TLA-listen@90> \* A SYN is reset only when nothing listens. One that the backlog has no
// TLA-listen@90> \* room for gets no answer, and its sender tries again.
// TLA-listen@90> FullIsSilent == [][\A p \in Peers : s'.refused[p] /\ ~s.refused[p] => ~s.c.open]_s
// TLA-listen@90> \* No place in the backlog is held for ever. A handshake ends, a
// TLA-listen@90> \* connection that is established is sent to Ruby, and Ruby's answers are
// TLA-listen@90> \* counted.
// TLA-listen@90> Shaken == \A p \in Peers : s.shaking[p] > 0 ~> s.shaking[p] = 0
// TLA-listen@90> Handed == \A p \in Peers : s.made[p] > 0 ~> s.made[p] = 0
// TLA-listen@90> Counted == s.c.answers > 0 ~> s.c.answers = 0 \/ ~s.c.open
//
// TLA-listen.cfg> SPECIFICATION Spec
// TLA-listen.cfg> CONSTANTS Peers = {p1, p2}
// TLA-listen.cfg>   Backlog = 1
// TLA-listen.cfg>   Holds = 2
// TLA-listen.cfg>   Fault = "none"
// TLA-listen.cfg> INVARIANTS Bounded Exact Fits NoStray OnePerPeer
// TLA-listen.cfg> PROPERTIES FullIsSilent Shaken Handed Counted
// TLA-listen.cfg> CHECK_DEADLOCK FALSE
//
// It is checked with room for two connections too, and with a third peer.
//
// TLA-listen.cfg/two> Backlog = 2
// TLA-listen.cfg/three> Peers = {p1, p2, p3}
// TLA-listen.cfg/three> Backlog = 2
//
// A pair may hold fewer connections than the backlog, as it does where the
// system's socket buffers are small. A connection then waits until Ruby
// takes one, and Ruby owes nothing. So this variant leaves out Handed,
// which says that the wait ends.
//
// TLA-listen.cfg/small-pair> Backlog = 2
// TLA-listen.cfg/small-pair> Holds = 1
// TLA-listen.cfg/small-pair> PROPERTIES FullIsSilent Shaken Counted
//
// Each of these variants has a fault that the code avoids, and the model
// finds each. A SYN is given a socket though a socket has its connection:
//
// TLA-listen.cfg/takes-twice!OnePerPeer> Fault = "takes twice"
//
// A socket that listens again after a reset is kept:
//
// TLA-listen.cfg/keeps-listeners!OnePerPeer> Fault = "keeps listeners"
//
// A socket is kept though smoltcp gave it no SYN:
//
// TLA-listen.cfg/keeps-its-socket!OnePerPeer> Fault = "keeps its socket"
//
// A SYN that the backlog has no room for goes to smoltcp, which resets it:
//
// TLA-listen.cfg/resets-when-full!FullIsSilent> Fault = "resets when full"
//
// The handshakes under way are not counted against the backlog:
//
// TLA-listen.cfg/counts-no-handshakes!Bounded> Fault = "counts no handshakes"
//
// Ruby's answers are not counted:
//
// TLA-listen.cfg/uncounted!Counted> Fault = "uncounted"

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::conn::{FIN_WAIT, SYN_WAIT};
    use crate::sock::{RECV_BUF, SEND_BUF, TCP_TIMEOUT};
    use smoltcp::socket::tcp;
    use smoltcp::time::Duration as SDuration;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    const A: &str = "10.9.0.1";
    const B: &str = "10.9.0.2";

    fn cfg(addr: &str) -> Config {
        let key = crate::keys::encode(&[1; 32]);
        config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {addr}")).unwrap()
    }

    fn stack(addr: &str) -> Stack {
        Stack::new(&cfg(addr), false, sys::epoll().unwrap())
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
            a.turn();
            b.turn();
            let mut moved = false;
            while let Some(packet) = a.transmit() {
                b.receive(packet);
                moved = true;
            }
            while let Some(packet) = b.transmit() {
                a.receive(packet);
                moved = true;
            }
            if !moved {
                break;
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
        let s = a.sockets.get::<Socket>(a.conns[0].handle);
        assert_eq!(s.congestion_control(), tcp::CongestionControl::Cubic);
        assert!(!s.nagle_enabled());
        assert_eq!(s.min_rto(), SDuration::from_millis(200));
        assert_eq!(s.ack_delay(), None);
    }

    #[test]
    fn a_syn_offers_selective_acknowledgement_only_if_the_stack_is_told_to() {
        let key = crate::keys::encode(&[1; 32]);
        let cfg = config::parse(&format!("[Interface]\nPrivateKey = {key}\nAddress = {A}")).unwrap();
        for sack in [false, true] {
            let mut a = Stack::new(&cfg, sack, sys::epoll().unwrap());
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
        for _ in 1..SYN_WAIT.as_secs() {
            age(&mut a, Duration::from_secs(1));
            a.turn();
            while a.transmit().is_some() {}
        }
        assert_eq!(read(&mut ruby), (vec![], false), "the attempt has a second left");
        age(&mut a, Duration::from_secs(1));
        a.turn();
        assert_eq!(read(&mut ruby), (vec![status::TIMED_OUT], true));
        assert!(is_reset(&a.transmit().unwrap()) && a.conns.is_empty());
    }

    #[test]
    fn an_attempt_that_is_refused_at_the_last_is_refused() {
        let (mut a, mut b) = (stack(A), stack(B));
        let mut ruby = connect(&mut a, B, 7);
        a.turn();
        while a.transmit().is_some() {}
        // The first SYNs are lost. B has no listener, and resets the SYN
        // that reaches it a second before A would give the attempt up.
        age(&mut a, SYN_WAIT - Duration::from_secs(1));
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![status::REFUSED], true));
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
    fn a_connection_that_ruby_cannot_be_told_of_is_not_kept() {
        let (mut a, mut b) = (stack(A), stack(B));
        let listener = listen(&mut b, 7, 4);
        assert_eq!(message(&listener), Some(vec![status::OK]));
        let client = connect(&mut a, B, 7);
        // Ruby's end takes no more, and so not the status. It has not
        // hung up: it may still write.
        client.shutdown(Shutdown::Read).unwrap();
        settle(&mut a, &mut b);
        assert!(a.conns.is_empty(), "A has reset the connection");
        // The reset came in place of the ACK that ends the handshake, so
        // B has no connection to send its listener.
        assert!(b.conns.is_empty() && message(&listener).is_none());
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
        assert!(
            b.conns.len() == 1 && matches!(b.conns[0].phase, Phase::Open(_)) && b.listeners[0].ctl.unaccepted() == 1
        );
        let from = format!("{A} {}", a.conns[0].local_port.unwrap());
        assert_eq!(message(&listener), Some(from.into_bytes()));
        // The message was read here without its descriptor. So the pair's
        // other end is closed, and B ends the connection.
        settle(&mut a, &mut b);
        assert_eq!(read(&mut ruby), (vec![], true));
        drop(ruby);
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
        assert_eq!(b.listeners[0].ctl.unaccepted(), 2);
    }

    #[test]
    fn a_connection_waits_for_room_in_the_pair_of_its_listener() {
        let (mut a, mut b) = (stack(A), stack(B));
        // The listener's pair is given a small buffer, as every pair has
        // on a system whose socket buffers are small. It then holds fewer
        // connections than the backlog.
        let (ours, theirs) = sys::socketpair(libc::SOCK_SEQPACKET).unwrap();
        let small: libc::c_int = 4096;
        unsafe { libc::setsockopt(ours.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, (&raw const small).cast(), 4) };
        b.listen(ours, 7, 32);
        let listener = UnixDatagram::from(theirs);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(message(&listener), Some(vec![status::OK]));
        let mut rubies: Vec<UnixStream> = (0..20).map(|_| connect(&mut a, B, 7)).collect();
        settle(&mut a, &mut b);
        assert!(rubies.iter_mut().all(|ruby| read(ruby) == (vec![status::OK], false)), "each handshake is over");
        let waiting = |b: &Stack| b.conns.iter().filter(|c| matches!(c.phase, Phase::Listening { .. })).count();
        let sent = b.listeners[0].ctl.unaccepted();
        assert!(sent > 0 && sent < 20, "the pair took {sent} of the 20");
        assert_eq!(waiting(&b), 20 - sent, "and the others wait, with none of them reset");
        // Ruby takes the connections one by one. Each makes room for one
        // that waits.
        for taken in 1..=20 {
            let _ruby = accept(&listener);
            settle(&mut a, &mut b);
            assert_eq!(waiting(&b), (20 - sent).saturating_sub(taken));
        }
        assert!(b.listeners[0].ctl.unaccepted() == 0 && a.conns.len() == 20);
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
    fn a_handshake_that_its_peer_leaves_is_given_up() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 1);
        let _ruby = connect(&mut a, B, 7);
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert!(!is_reset(&b.transmit().unwrap()), "the SYN is answered");
        // The answer is lost, and A sends no more.
        age(&mut b, SYN_WAIT - Duration::from_secs(1));
        b.turn();
        assert!(std::iter::from_fn(|| b.transmit()).all(|packet| !is_reset(&packet)) && b.conns.len() == 1);
        age(&mut b, Duration::from_secs(1));
        b.turn();
        assert!(std::iter::from_fn(|| b.transmit()).any(|packet| is_reset(&packet)));
        assert!(b.conns.is_empty(), "and its place in the backlog is free");
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
        // The socket that owed the last ACK has sent it, and is gone.
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
        stack.sockets.get::<Socket>(stack.conns[0].handle).recv_queue()
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
        assert_eq!(a.sockets.get::<Socket>(a.conns[0].handle).state(), tcp::State::Established);
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
    fn a_syn_that_smoltcp_gives_to_no_socket_leaves_none_listening() {
        let (mut a, mut b) = (stack(A), stack(B));
        let _listener = listen(&mut b, 7, 4);
        // The SYN is to the port that B listens on, at an address that B
        // does not have.
        let _ruby = connect(&mut a, "10.9.0.3", 7);
        a.turn();
        b.receive(a.transmit().unwrap());
        b.turn();
        assert!(b.conns.is_empty() && b.transmit().is_none());
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
        let s = b.sockets.get::<Socket>(b.conns[0].handle);
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
        let state = |a: &Stack| a.sockets.get::<Socket>(a.conns[0].handle).state();
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
    fn a_connection_that_ends_sends_its_last_ack_in_the_same_turn() {
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
        let ack = a.transmit().expect("the ACK of the peer's FIN");
        assert!(!is_reset(&ack) && a.transmit().is_none());
        assert!(a.finished(), "and the connection's socket is gone");
        assert_eq!(read(&mut client), (b"bye".to_vec(), true));
    }

    #[test]
    fn a_fin_that_comes_again_finds_no_socket_and_is_reset() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (mut client, mut server) = connected(&mut a, &mut b);
        client.shutdown(Shutdown::Write).unwrap();
        settle(&mut a, &mut b);
        assert_eq!(read(&mut server), (vec![], true));
        drop(server);
        b.turn();
        let fin = b.transmit().expect("B's FIN");
        a.receive(fin.clone());
        a.turn();
        // A's socket has sent its last ACK and is gone. The ACK is lost,
        // and B sends its FIN again.
        assert!(a.transmit().is_some_and(|ack| !is_reset(&ack)) && a.finished());
        a.receive(fin);
        a.turn();
        let answer = a.transmit().expect("an answer to the FIN");
        assert!(is_reset(&answer));
        // To B the reset ends the connection, as the ACK would have.
        b.receive(answer);
        b.turn();
        assert!(b.conns.is_empty());
        assert_eq!(read(&mut client), (vec![], true));
    }

    #[test]
    fn a_connection_has_cause_for_a_pass_when_something_happens_to_it() {
        let (mut a, mut b) = (stack(A), stack(B));
        let listener = listen(&mut b, 7, 4);
        assert_eq!(message(&listener), Some(vec![status::OK]));
        let mut clients = [connect(&mut a, B, 7), connect(&mut a, B, 7)];
        settle(&mut a, &mut b);
        let mut servers = [accept(&listener), accept(&listener)];
        settle(&mut a, &mut b);
        let cause = |stack: &Stack| stack.conns.iter().map(|c| c.cause).collect::<Vec<_>>();
        assert_eq!(cause(&a), [false, false], "a turn leaves every connection at rest");
        // Ruby writes to the second connection, and the epoll set reports
        // that pair.
        clients[1].write_all(b"from Ruby").unwrap();
        a.stir();
        assert_eq!(cause(&a), [false, true]);
        settle(&mut a, &mut b);
        // A packet arrives for the first.
        servers[0].write_all(b"from the peer").unwrap();
        b.turn();
        a.receive(b.transmit().unwrap());
        a.ingress();
        assert_eq!(cause(&a), [true, false]);
        settle(&mut a, &mut b);
        assert_eq!(read(&mut clients[0]).0.len(), 1 + b"from the peer".len());
        // Four times a second the loop looks at every connection.
        age(&mut a, CHECK);
        a.stir();
        assert_eq!(cause(&a), [true, true]);
    }

    #[test]
    fn a_dead_connection_stays_until_its_socket_owes_nothing() {
        let (mut a, mut b) = (stack(A), stack(B));
        let (client, mut server) = connected(&mut a, &mut b);
        server.write_all(b"unread").unwrap();
        settle(&mut a, &mut b);
        // The client leaves bytes unread, and the pass resets the peer
        // for them. Until the sockets have sent, the socket owes the
        // reset.
        drop(client);
        a.pump();
        a.sweep();
        assert!(matches!(a.conns[..], [Conn { phase: Phase::Dead, .. }]) && a.transmit().is_none());
        a.poll();
        a.sweep();
        assert!(a.conns.is_empty() && is_reset(&a.transmit().unwrap()));
    }

    #[test]
    fn a_connection_that_ends_goes_though_another_has_more_to_send() {
        // B's link takes packets of 88 bytes, which is less than the
        // parser allows. So B asks for segments of 48 bytes, the smallest
        // that smoltcp agrees to. A turn has a socket send EGRESS_ROUNDS
        // packets at the most, and B's window takes more segments than
        // that.
        let (mut a, mut b) = (stack(A), Stack::new(&Config { mtu: 88, ..cfg(B) }, false, sys::epoll().unwrap()));
        let (mut bulk, mut sink) = connected(&mut a, &mut b);
        // A's congestion window grows by a segment for each ACK, and B
        // acknowledges once in a turn. So B takes each segment in a turn
        // of its own, until A may send as much as B's window takes.
        let mut at = 0;
        loop {
            at = write_from(&mut bulk, at, 1 << 16);
            a.turn();
            let sent: Vec<Vec<u8>> = std::iter::from_fn(|| a.transmit()).collect();
            if sent.is_empty() {
                break;
            }
            for packet in sent {
                b.receive(packet);
                b.turn();
                read(&mut sink);
                while let Some(ack) = b.transmit() {
                    a.receive(ack);
                }
            }
        }
        let (other, mut server) = connected(&mut a, &mut b);
        server.write_all(b"unread").unwrap();
        settle(&mut a, &mut b);
        // The second connection ends in a turn that leaves segments of
        // the first unsent.
        write_from(&mut bulk, at, at + (1 << 16));
        drop(other);
        a.turn();
        let sent: Vec<Vec<u8>> = std::iter::from_fn(|| a.transmit()).collect();
        assert!(sent.len() > EGRESS_ROUNDS && a.poll_delay() == Some(Duration::ZERO), "the turn left segments unsent");
        assert_eq!(sent.iter().filter(|packet| is_reset(packet)).count(), 1, "and it sent the reset");
        assert_eq!(a.conns.len(), 1, "so the socket that owed the reset is gone");
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

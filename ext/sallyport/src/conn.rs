//! This file has what one TCP connection of a tunnel does, for the whole
//! of its life. A connection goes through phases, and step moves it on.
//! An open connection has a Unix socket pair and a TCP socket, and carry
//! moves bytes between the two.
//!
//! The file asks nothing of the kernel or of smoltcp but through pair.rs,
//! ctl.rs and sock.rs. The model "conn" is of what is here and of the
//! part of the stack's loop that turns it, which is in tcp.rs.

use crate::ctl::Ctl;
use crate::pair::{Gave, Hangup, Pair, Took};
use crate::sock::{Opening, Sock, Socket, Up, TCP_TIMEOUT};
use crate::sys;
use std::collections::VecDeque;
use std::time::Duration;

/// A connection that Ruby has closed is given this long to hear the
/// peer's FIN, once the peer has acknowledged ours. Linux gives as long.
pub const FIN_WAIT: Duration = Duration::from_secs(60);

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

/// A connection is in one of these phases, and a phase holds what the
/// connection has only then. Each time is read from the stack's clock.
pub enum Phase {
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
    Open(Open),
    /// The connection is closed to Ruby and has no pair. Its socket stays
    /// until it has sent what it owes the peer.
    Dead {
        since: Duration,
    },
}

/// What an open connection has besides its socket.
pub struct Open {
    pub pair: Pair,
    /// When poll first reported a hangup on our end. Either Ruby has
    /// closed its end, or each side has shut down its writing, which poll
    /// does not tell apart. In both cases Ruby has no more to say, and
    /// has been told all that it will be.
    pub left: Option<Duration>,
    /// Since when the connection has waited for nothing but the peer's
    /// FIN: Ruby has left, and the peer has acknowledged our FIN.
    wait: Option<Duration>,
    /// The tail holds what the peer sent last and Ruby has yet to be
    /// given, once that is taken out of the socket's buffer.
    pub tail: VecDeque<u8>,
}

impl Phase {
    /// Returns the phase of a connection that has just become open.
    fn open(pair: Pair) -> Phase {
        Phase::Open(Open { pair, left: None, wait: None, tail: VecDeque::new() })
    }
}

/// A step decides one of these for its connection.
pub enum Fate {
    /// The connection goes on, in this phase.
    Keep(Phase),
    /// Close our end of the pair. The TCP connection has ended by itself.
    Close,
    /// Close our end of the pair, and reset the TCP connection.
    Abort,
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
// sock.rs. The lines of the model are beside the code that they describe.
// Those for what the stack's loop does are in tcp.rs. `rake tla` checks
// the model.
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
// TLA-conn@0> Init == \E first \in {"connecting", "listening"} : s = [
// TLA-conn@0>   p       |-> P!New,    \* the pair
// TLA-conn@0>   k       |-> K!New,    \* the socket
// TLA-conn@0>   phase   |-> first,    \* "connecting", "listening", "open", "dead" or "removed"
// TLA-conn@0>   old     |-> FALSE,    \* the phase is old: an attempt as smoltcp's timeout, a dead socket as LINGER
// TLA-conn@0>   said    |-> "none",   \* what Ruby was told of the attempt: "ok", "refused" or "timedout"
// TLA-conn@0>   listens |-> TRUE,     \* Ruby has not closed the listener
// TLA-conn@0>   left    |-> "no",     \* Open.left is "no", "yes" or "late" (TCP_TIMEOUT ago)
// TLA-conn@0>   wait    |-> "no",     \* Open.wait is "no", "yes" or "late" (FIN_WAIT ago)
// TLA-conn@0>   closing |-> FALSE,    \* Stack.closing
// TLA-conn@0>   at      |-> "idle",   \* where the thread is in a pass over the connection
// TLA-conn@0>   kick    |-> FALSE]    \* poll will return, whatever it reports of the pair
// TLA-conn@0> Early == {"connecting", "listening"}
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
// TLA-conn@10> \* Ruby may close the listener while a handshake is under way, and poll
// TLA-conn@10> \* reports that.
// TLA-conn@10> ListenerCloses == /\ s.phase = "listening" /\ s.listens
// TLA-conn@10>                   /\ s' = [s EXCEPT !.listens = FALSE, !.kick = TRUE]
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

// TLA-conn@20> \* A pass ends in one of these ways. A connection that is closed or reset
// TLA-conn@20> \* keeps its socket, as Phase::Dead, until the socket has sent what it owes.
// TLA-conn@20> Rest(t) == [t EXCEPT !.at = "idle"]
// TLA-conn@20> Dead(t) == [t EXCEPT !.phase = IF Fault = "remove at once" THEN "removed" ELSE "dead",
// TLA-conn@20>                      !.old = FALSE, !.at = "idle"]
// TLA-conn@20> Close(t) == Dead(t)
// TLA-conn@20> Abort(t) == Dead([t EXCEPT !.k = K!Abort(@)])
// TLA-conn> \* step, for a connection that is not open yet. Ruby is told of a
// TLA-conn> \* connection once, when its handshake is over: with the status of one
// TLA-conn> \* that it makes, or with the descriptor of one that it accepts. The
// TLA-conn> \* listener's pair has room for the descriptor, as the model "listen"
// TLA-conn> \* shows. A connection that becomes open is carried in the same pass.
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
// TLA-conn>          ELSE IF K!Opening(t.k) = "done" THEN [t EXCEPT !.said = "ok", !.phase = "open", !.at = "take"]
// TLA-conn>          ELSE IF K!Opening(t.k) = "failed" /\ Fault # "keeps a failure" THEN Close(t)
// TLA-conn>          ELSE Rest(t)
/// Moves one connection as far as it will go, through each phase that it
/// can leave now, and says what becomes of it. `ctl` is the pair of the
/// listener that a connection in Phase::Listening waits for, and there is
/// none if Ruby has closed that listener.
pub fn step(mut phase: Phase, s: &mut Socket, mut ctl: Option<&mut Ctl>, now: Duration, closing: bool) -> Fate {
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
            Phase::Listening { .. } => {
                // Ruby closed the listener.
                let Some(ctl) = ctl.as_deref_mut() else { return Fate::Abort };
                match Sock::opening(s) {
                    Opening::Pending => return Fate::Keep(phase),
                    // The peer left the handshake unfinished, or it
                    // finished the handshake and reset the connection at
                    // once.
                    Opening::Failed => return Fate::Close,
                    Opening::Done => {
                        // The system may have no descriptors to spare.
                        let Ok((ours, theirs)) = sys::socketpair(libc::SOCK_STREAM) else { return Fate::Abort };
                        let Some(from) = Sock::peer(s) else { return Fate::Abort };
                        // Ruby may have closed the listener a moment ago.
                        if !ctl.send(&format!("{} {}", from.addr, from.port), &theirs) {
                            return Fate::Abort;
                        }
                        Phase::open(Pair::new(ours))
                    }
                }
            }
            Phase::Open(open) => return carry(open, s, now, closing),
        };
    }
}

/// Moves bytes each way for an open connection, and passes on the end of
/// each direction.
fn carry(mut open: Open, s: &mut Socket, now: Duration, closing: bool) -> Fate {
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
    // TLA-conn> Fin(t) == IF t.k.up = "open" /\ t.p.done /\ (K!AllAcked(t.k) \/ Fault = "early fin")
    // TLA-conn>           THEN [t EXCEPT !.k = K!End(@)] ELSE t
    // TLA-conn> Onward(t) == [Fin(t) EXCEPT !.at = "give"]
    // TLA-conn> Take(t) ==
    // TLA-conn>   IF ~t.p.done /\ t.k.up # "open" /\ Fault # "writes on" THEN Onward([t EXCEPT !.p = P!Stop(@)])
    // TLA-conn>   ELSE IF t.p.done \/ ~K!HasRoom(t.k) THEN Onward(t)
    // TLA-conn>   ELSE LET n == Min(t.p.fromRuby, K!Room(t.k))
    // TLA-conn>            u == [t EXCEPT !.p = P!Took(@, n), !.k = K!Filled(@, n)]
    // TLA-conn>        IN CASE P!Read(t.p) = "bytes" -> u
    // TLA-conn>             [] P!Read(t.p) = "reset" -> Abort(u)
    // TLA-conn>             [] OTHER -> Onward(u)
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
    // TLA-conn>   IF t.p.deaf \/ ~K!Holds(t.k) THEN [t EXCEPT !.at = "end"]
    // TLA-conn>   ELSE LET n == Min(t.k.rx, P!Room(t.p))
    // TLA-conn>            lost == IF Fault = "drops" /\ P!Write(t.p) = "refused" THEN t.k.rx ELSE 0
    // TLA-conn>            u == [t EXCEPT !.p = P!Gave(@, n), !.k = K!Drained(@, n + lost)]
    // TLA-conn>        IN IF P!Write(t.p) = "bytes" THEN u ELSE [u EXCEPT !.at = "end"]
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
    // TLA-conn> End(t) == IF ~t.p.told /\ ~t.k.down /\ ~K!Holds(t.k)
    // TLA-conn>           THEN [t EXCEPT !.p = P!End(@), !.at = "judge"]
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
    // TLA-conn>       ELSE IF v.k.up = "ended" /\ ~v.k.down /\ (v.p.told \/ Fault = "early close") THEN Close(v)
    // TLA-conn>       ELSE IF v.left # "no" /\ K!Holds(v.k) /\ Fault # "keeps unread" THEN Abort(v)
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
// TLA-conn@90> Next == \/ RubyActs \/ ListenerCloses \/ PeerPacket \/ PeerSilent
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
// TLA-conn@90> NoneWithheld == s.p.told => s.k.rx = 0
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
// TLA-conn@90> \* A connection that is cut does not rest while Ruby may write to it. A
// TLA-conn@90> \* write by Ruby fails, as a write to a TCP socket does once it is reset.
// TLA-conn@90> CutStops == Asleep(s) /\ s.phase = "open" /\ s.k.cut => s.p.fromShut
// TLA-conn@90> \* Nor does a connection rest while Ruby has left and the socket holds
// TLA-conn@90> \* bytes for it. The peer is reset for them, as a TCP socket of the kernel
// TLA-conn@90> \* resets it when it is closed with bytes unread.
// TLA-conn@90> NoneOrphaned == Asleep(s) /\ s.phase = "open" /\ s.left # "no" => ~K!Holds(s.k)
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
// TLA-conn@90>                    open |-> s.phase \in Live /\ ~s.p.told, done |-> ~s.k.down],
// TLA-conn@90>          up |-> [src |-> s.p.fromRuby, dst |-> IF s.phase \in Live THEN s.k.tx ELSE 0,
// TLA-conn@90>                  open |-> s.phase \in Live /\ s.k.up = "open", done |-> s.p.done],
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
// TLA-conn@90>                ~> \/ ~K!Holds(s.k) /\ (s.k.down \/ s.p.told)
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
// TLA-conn@90> CleanEof == s.p.told /\ s.p.gone = "no" => s.k.fin
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
// TLA-conn.cfg>   NoMissedWake NoSpin CutStops NoneOrphaned OpenIsGreeted SaidAtTheEnd
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
// A connection that the peer has reset goes on taking what Ruby writes:
//
// TLA-conn.cfg/writes-on!CutStops> Fault = "writes on"
//
// A connection keeps the bytes that the peer sends once Ruby has left:
//
// TLA-conn.cfg/keeps-unread!NoneOrphaned> Fault = "keeps unread"
//
// A tunnel that is closing leaves each pair as it is, and then resets
// connections whose Ruby has not left:
//
// TLA-conn.cfg/closes-quietly!Kept> Fault = "closes quietly"
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

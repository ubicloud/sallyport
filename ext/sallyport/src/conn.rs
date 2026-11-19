//! This file has what one TCP connection of a tunnel does, for the whole
//! of its life. A connection goes through phases, and step moves it on.
//! An open connection has a Unix socket pair and a TCP socket, and carry
//! moves bytes between the two.
//!
//! The file asks nothing of the kernel or of smoltcp but through pair.rs,
//! ctl.rs and sock.rs. The model "conn" is of what is here and of the
//! part of the stack's loop that turns it, which is in tcp.rs.

use crate::ctl::Ctl;
use crate::pair::{Gave, Hangup, Pair, PairCalls, Took};
use crate::sock::{Opening, Sock, SockCalls, Socket, Up, TCP_TIMEOUT};
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

// TLA-conn@20> \* A pass ends in one of these ways. A connection that is closed or reset
// TLA-conn@20> \* keeps its socket, as Phase::Dead, until the socket has sent what it owes.
// TLA-conn@20> Rest(t) == [t EXCEPT !.at = "idle"]
// TLA-conn@20> Dead(t) == [t EXCEPT !.phase = IF Fault = "remove at once" THEN "removed" ELSE "dead",
// TLA-conn@20>                      !.old = FALSE, !.at = "idle"]
// TLA-conn@20> Close(t) == Dead(t)
// TLA-conn@20> Abort(t) == Dead([t EXCEPT !.k = K!Abort(@)])
/// A pass over a connection ends in one of these ways.
enum Fate {
    /// The connection goes on.
    Rest,
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
/// can leave now, and returns the phase that it is then in. `ctl` is the
/// pair of the listener that a connection in Phase::Listening waits for,
/// and there is none if Ruby has closed that listener.
pub fn step(mut phase: Phase, s: &mut Socket, mut ctl: Option<&mut Ctl>, now: Duration, closing: bool) -> Phase {
    let fate = loop {
        phase = match phase {
            // sweep removes it.
            Phase::Dead { .. } => return phase,
            // Ruby gave up waiting, and closed its end. Or the tunnel is
            // closing, and has shut the pair down.
            Phase::Connecting { pair, .. } if pair.hangup() != Hangup::No => break Fate::Abort,
            Phase::Connecting { pair, since } => match Sock::opening(s) {
                // The peer answers a SYN with a bare SYN if it was
                // connecting to us at the same moment, and the handshake
                // is not over.
                Opening::Pending => return Phase::Connecting { pair, since },
                Opening::Failed => {
                    // smoltcp does not say whether a reset or its timeout
                    // closed the socket, so the time taken has to.
                    let late = now - since + Duration::from_secs(1) >= TCP_TIMEOUT;
                    pair.say(if late { status::TIMED_OUT } else { status::REFUSED });
                    break Fate::Close;
                }
                Opening::Done => {
                    pair.say(status::OK);
                    Phase::open(pair)
                }
            },
            Phase::Listening { .. } => {
                // Ruby closed the listener.
                let Some(ctl) = ctl.as_deref_mut() else { break Fate::Abort };
                match Sock::opening(s) {
                    Opening::Pending => return phase,
                    // The peer left the handshake unfinished, or it
                    // finished the handshake and reset the connection at
                    // once.
                    Opening::Failed => break Fate::Close,
                    Opening::Done => {
                        // The system may have no descriptors to spare.
                        let Ok((ours, theirs)) = sys::socketpair(libc::SOCK_STREAM) else { break Fate::Abort };
                        let Some(from) = Sock::peer(s) else { break Fate::Abort };
                        // Ruby may have closed the listener a moment ago.
                        if !ctl.send(&format!("{} {}", from.addr, from.port), &theirs) {
                            break Fate::Abort;
                        }
                        Phase::open(Pair::new(ours))
                    }
                }
            }
            Phase::Open(mut open) => {
                let Open { pair, left, wait, tail } = &mut open;
                // The socket's contract has the tail, and carry has the
                // rest.
                match carry(pair, &mut Sock::new(s, tail), left, wait, now, closing) {
                    Fate::Rest => return Phase::Open(open),
                    over => break over,
                }
            }
        };
    };
    // The connection is over for Ruby, and our end of the pair is closed
    // with the phase that held it. The socket has a reset or a last ACK
    // to send, and stays until it has sent it.
    if let Fate::Abort = fate {
        Sock::abort(s);
    }
    Phase::Dead { since: now }
}

// TLA-conn> \* A pass of carry is four steps, and each makes one kind of call on the
// TLA-conn> \* pair. Ruby may act between two calls.
/// Moves bytes each way for an open connection, passes on the end of
/// each direction, and says how the pass ends. `left` and `wait` are
/// those of Open. A pass is four steps, which the model has by the same
/// names. Neither carry nor a step asks anything of the pair and of the
/// socket but through their calls, so a test can give them the pair and
/// the socket of the model.
fn carry(
    pair: &mut impl PairCalls,
    s: &mut impl SockCalls,
    left: &mut Option<Duration>,
    wait: &mut Option<Duration>,
    now: Duration,
    closing: bool,
) -> Fate {
    if let Some(over) = take(pair, s) {
        return over;
    }
    give(pair, s);
    end(pair, s);
    judge(pair, s, left, wait, now, closing)
}

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
/// Takes what Ruby wrote, for as much as the socket has room, and ends
/// the stream to the peer when Ruby has ended its own. It says how the
/// pass ends if the pass ends here.
fn take(pair: &mut impl PairCalls, s: &mut impl SockCalls) -> Option<Fate> {
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
            Some(Took::Reset) => return Some(Fate::Abort),
            Some(Took::End | Took::Nothing) | None => break,
        }
    }
    if s.up() == Up::Open && pair.done() && s.all_acknowledged() {
        s.end();
    }
    None
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
/// Gives Ruby what the socket holds, for as much as the pair has room.
/// The socket keeps what the pair refuses. A TCP socket of the kernel
/// keeps such bytes too, and the peer is held once the socket is full.
/// Nothing is dropped while the connection lasts.
fn give(pair: &mut impl PairCalls, s: &mut impl SockCalls) {
    while !pair.deaf() && s.holds() {
        if !matches!(s.drain(|buf| pair.write(buf)), Some(Gave::Bytes(_))) {
            break;
        }
    }
}

// TLA-conn> \* The third step ends what Ruby reads, when the peer has ended its
// TLA-conn> \* stream and Ruby has been given all of it.
// TLA-conn> End(t) == IF ~t.p.told /\ ~t.k.down /\ ~K!Holds(t.k)
// TLA-conn>           THEN [t EXCEPT !.p = P!End(@), !.at = "judge"]
// TLA-conn>           ELSE [t EXCEPT !.at = "judge"]
/// Ends what Ruby reads, when the peer has ended its stream and Ruby has
/// been given all of it.
fn end(pair: &mut impl PairCalls, s: &impl SockCalls) {
    if !pair.told() && !s.down_open() && !s.holds() {
        pair.end();
    }
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
/// Asks poll whether Ruby has left, and decides what becomes of the
/// connection. The two times of a connection that Ruby has left begin
/// here.
fn judge(
    pair: &impl PairCalls,
    s: &impl SockCalls,
    left: &mut Option<Duration>,
    wait: &mut Option<Duration>,
    now: Duration,
    closing: bool,
) -> Fate {
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
        _ => Fate::Rest,
    }
}

// TLA-conn> \* asks. The pair is read while the socket has room, and written while
// TLA-conn> \* the socket holds bytes that the pair has not refused. A descriptor with
// TLA-conn> \* neither asked of it is watched for a hangup, until the hangup has been
// TLA-conn> \* seen.
// TLA-conn> AskIn(t) == ~t.p.done /\ K!HasRoom(t.k) /\ Fault # "reads unasked"
// TLA-conn> AskOut(t) == K!Holds(t.k) /\ (~t.p.deaf \/ Fault = "deaf asks") /\ Fault # "writes unasked"
// TLA-conn> Watched(t) == \/ AskIn(t) \/ AskOut(t)
// TLA-conn>               \/ t.left = "no" /\ Fault # "hangup unwatched"
// TLA-conn>               \/ Fault = "hangup always watched"
/// Says which events poll is to be asked about for the pair of an open
/// connection, or says nothing if poll is not to watch the pair. `room`
/// and `holds` are what Sock::asks says of the socket, and `left` is
/// whether poll has reported a hangup.
fn asks(pair: &impl PairCalls, room: bool, holds: bool, left: bool) -> Option<libc::c_short> {
    // The pair is read while the socket has room, and written while the
    // socket has bytes for Ruby, unless the pair has refused them.
    let read = if !pair.done() && room { libc::POLLIN } else { 0 };
    let write = if holds && !pair.deaf() { libc::POLLOUT } else { 0 };
    // poll reports a hangup whether asked or not. So a descriptor with
    // no events asked of it is watched for Ruby closing its end, and for
    // nothing else. Once the hangup has been seen, poll would return for
    // it for ever.
    (read | write != 0 || !left).then_some(read | write)
}

impl Phase {
    // TLA-conn> \* FdReady says whether poll returns for the descriptor. It reports a
    // TLA-conn> \* hangup, and bytes that Ruby left unread, whatever it is asked. A
    // TLA-conn> \* connection that Ruby makes is watched for Ruby giving it up.
    // TLA-conn> FdReady(t) == CASE t.phase = "open" -> /\ Watched(t)
    // TLA-conn>                                        /\ \/ AskIn(t) /\ P!Readable(t.p)
    // TLA-conn>                                           \/ AskOut(t) /\ P!Writable(t.p)
    // TLA-conn>                                           \/ P!HungUp(t.p) \/ P!Unread(t.p)
    // TLA-conn>                 [] t.phase = "connecting" -> P!HungUp(t.p)
    // TLA-conn>                 [] OTHER -> FALSE
    /// Returns what poll is to watch for a connection in this phase: our
    /// end of its pair, and the events to ask about. A phase that has no
    /// pair has nothing to watch.
    pub fn watch(&self, s: &Socket) -> Option<libc::pollfd> {
        let (pair, events) = match self {
            Phase::Listening { .. } | Phase::Dead { .. } => return None,
            // Ruby may write before it has the status, and nothing reads
            // that yet. So poll is not asked whether there is anything to
            // read, for which it would return for ever.
            Phase::Connecting { pair, .. } => (pair, 0),
            Phase::Open(Open { pair, left, tail, .. }) => {
                let (room, holds) = Sock::asks(s, tail);
                (pair, asks(pair, room, holds, left.is_some())?)
            }
        };
        Some(libc::pollfd { fd: pair.raw(), events, revents: 0 })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sock::Moved;
    use std::collections::HashMap;

    // The model says what carry does, and this test holds carry to it. For
    // each state of an open connection, the model gives what poll is
    // asked, and the state after a whole pass or after the step that the
    // state is at. `rake conform` has TLC write that for every state that
    // it reaches. The test then gives carry, or the step, a pair and a
    // socket that are the records of the modules "pair" and "sock", in
    // each of those states.
    //
    // TLA-conn@95> \* tools/tla writes the elements of Passes for a test in conn.rs, which
    // TLA-conn@95> \* holds carry, its four steps and asks to them. Sight is what those can
    // TLA-conn@95> \* see of a state, and what they can change.
    // TLA-conn@95> Sight(t) == [pair |-> [f \in DOMAIN t.p \ {"quota"} |-> t.p[f]],
    // TLA-conn@95>              sock |-> [f \in {"up", "down", "tx", "rx", "cut", "owed"} |-> t.k[f]],
    // TLA-conn@95>              left |-> t.left, wait |-> t.wait, closing |-> t.closing, phase |-> t.phase]
    // TLA-conn@95> \* A step comes again while it moves bytes. Whole is the state when the
    // TLA-conn@95> \* step that a state is at has come for the last time.
    // TLA-conn@95> RECURSIVE Whole(_)
    // TLA-conn@95> Whole(t) == LET u == StepAt(t) IN IF u.at = t.at THEN Whole(u) ELSE u
    // TLA-conn@95> \* For an open connection at rest, Passes has the state after a whole
    // TLA-conn@95> \* pass. For one that is at a step, it has the state after that step,
    // TLA-conn@95> \* which Ruby may have come to by acting between two steps.
    // TLA-conn@95> Passes == IF s.phase # "open" THEN {}
    // TLA-conn@95>           ELSE {[at |-> s.at, from |-> Sight(s),
    // TLA-conn@95>                  to |-> Sight(IF s.at = "idle" THEN Pass(s) ELSE Whole(s)),
    // TLA-conn@95>                  asks |-> [read |-> AskIn(s), write |-> AskOut(s), watched |-> Watched(s)],
    // TLA-conn@95>                  caps |-> [pair |-> PairCap, tx |-> TxCap]]}

    /// Reads a record as TLC prints it. Returns each field's value under
    /// its path, as "from.pair.done". A string has lost its quotes.
    fn fields(record: &str) -> HashMap<String, String> {
        let (mut fields, mut path) = (HashMap::new(), Vec::new());
        let mut rest = record.strip_prefix('[').expect("a record");
        loop {
            rest = rest.trim_start_matches([' ', ',']);
            if let Some(after) = rest.strip_prefix(']') {
                rest = after;
                if path.pop().is_none() {
                    break;
                }
                continue;
            }
            let (name, after) = rest.split_once(" |-> ").expect("a field");
            path.push(name);
            if let Some(inner) = after.strip_prefix('[') {
                rest = inner;
                continue;
            }
            let end = after.find([',', ']']).expect("the end of a value");
            fields.insert(path.join("."), after[..end].trim_matches('"').to_string());
            path.pop();
            rest = &after[end..];
        }
        assert!(rest.is_empty(), "a record ends with its bracket");
        fields
    }

    /// A pair that is the record of the module "pair". Each call does
    /// what the module says of it.
    #[derive(Debug, PartialEq)]
    struct ModelPair {
        from_ruby: usize,
        for_ruby: usize,
        from_shut: bool,
        for_shut: bool,
        gone: String,
        err: bool,
        done: bool,
        deaf: bool,
        told: bool,
        cap: usize,
    }

    impl PairCalls for ModelPair {
        fn read(&mut self, buf: &mut [u8]) -> Took {
            if self.from_ruby > 0 {
                let n = self.from_ruby.min(buf.len());
                self.from_ruby -= n;
                Took::Bytes(n)
            } else if self.err {
                self.err = false;
                Took::Reset
            } else if self.from_shut {
                self.done = true;
                Took::End
            } else {
                Took::Nothing
            }
        }

        fn done(&self) -> bool {
            self.done
        }

        fn stop(&mut self) {
            (self.from_shut, self.done) = (true, true);
        }

        fn write(&mut self, buf: &[u8]) -> Gave {
            if self.for_shut || self.gone != "no" {
                self.deaf = true;
                Gave::Refused
            } else if self.for_ruby < self.cap {
                let n = buf.len().min(self.cap - self.for_ruby);
                self.for_ruby += n;
                Gave::Bytes(n)
            } else {
                Gave::Full
            }
        }

        fn deaf(&self) -> bool {
            self.deaf
        }

        fn end(&mut self) {
            (self.for_shut, self.told) = (true, true);
        }

        fn told(&self) -> bool {
            self.told
        }

        fn hangup(&self) -> Hangup {
            match (self.from_shut && self.for_shut, self.err) {
                (true, true) => Hangup::Unread,
                (true, false) => Hangup::Yes,
                (false, _) => Hangup::No,
            }
        }
    }

    /// A socket that is the record of the module "sock", as far as carry
    /// can see it. Each call does what the module says of it.
    #[derive(Debug, PartialEq)]
    struct ModelSock {
        up: Up,
        down: bool,
        tx: usize,
        rx: usize,
        cut: bool,
        owed: String,
        cap: usize,
    }

    impl SockCalls for ModelSock {
        fn up(&self) -> Up {
            self.up
        }

        fn down_open(&self) -> bool {
            self.down
        }

        fn has_room(&self) -> bool {
            self.up == Up::Open && self.tx < self.cap
        }

        fn fill<R: Moved>(&mut self, read: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
            let found = self.has_room().then(|| read(&mut vec![0; self.cap - self.tx]))?;
            self.tx += found.bytes();
            Some(found)
        }

        fn all_acknowledged(&self) -> bool {
            self.tx == 0
        }

        fn end(&mut self) {
            self.up = Up::Ending;
        }

        fn holds(&self) -> bool {
            self.rx > 0
        }

        fn drain<R: Moved>(&mut self, write: impl FnOnce(&[u8]) -> R) -> Option<R> {
            let found = self.holds().then(|| write(&vec![0; self.rx]))?;
            self.rx -= found.bytes();
            Some(found)
        }
    }

    impl ModelSock {
        /// Does what the module says of Sock::abort.
        fn abort(&mut self) {
            if !self.cut {
                self.owed = "rst".into();
            }
            (self.up, self.down, self.cut, self.tx) = (Up::Ended, false, true, 0);
        }
    }

    /// What Sight is of a state, with the phase and the two times as the
    /// model names them.
    type Sight = (ModelPair, ModelSock, String, String, String);

    /// Returns the half of a line of Passes that is under `side`.
    fn sight(f: &HashMap<String, String>, side: &str) -> Sight {
        let text = |name: &str| f[&format!("{side}.{name}")].clone();
        let flag = |name: &str| text(name) == "TRUE";
        let count = |name: &str| text(name).parse::<usize>().unwrap();
        let pair = ModelPair {
            from_ruby: count("pair.fromRuby"),
            for_ruby: count("pair.forRuby"),
            from_shut: flag("pair.fromShut"),
            for_shut: flag("pair.forShut"),
            gone: text("pair.gone"),
            err: flag("pair.err"),
            done: flag("pair.done"),
            deaf: flag("pair.deaf"),
            told: flag("pair.told"),
            cap: f["caps.pair"].parse().unwrap(),
        };
        let up = match text("sock.up").as_str() {
            "open" => Up::Open,
            "ending" => Up::Ending,
            _ => Up::Ended,
        };
        let sock = ModelSock {
            up,
            down: flag("sock.down"),
            tx: count("sock.tx"),
            rx: count("sock.rx"),
            cut: flag("sock.cut"),
            owed: text("sock.owed"),
            cap: f["caps.tx"].parse().unwrap(),
        };
        (pair, sock, text("left"), text("wait"), text("phase"))
    }

    /// The moment of each pass that the test makes.
    const NOW: Duration = Duration::from_secs(1_000_000);

    /// Returns one of the two times of an open connection as the model
    /// names it. The time is late when it began `limit` ago.
    fn named(since: Option<Duration>, limit: Duration) -> &'static str {
        match since {
            None => "no",
            Some(since) if NOW - since >= limit => "late",
            Some(_) => "yes",
        }
    }

    /// Returns a time that the model names so.
    fn since(name: &str, limit: Duration) -> Option<Duration> {
        match name {
            "no" => None,
            "late" => Some(NOW - limit),
            _ => Some(NOW - Duration::from_secs(1)),
        }
    }

    #[test]
    fn carry_and_its_steps_do_what_the_model_says_in_every_state_that_tlc_reaches() {
        // `rake conform` names the file that TLC wrote. Without the file
        // there is nothing to hold carry to, as a Ruby test has nothing
        // to run against without its fixture.
        let Some(path) = std::env::var_os("SALLYPORT_PASSES") else { return };
        let passes = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert!(passes.lines().count() > 1000, "TLC reaches more states than {path:?} has");
        for line in passes.lines() {
            let f = fields(line);
            let (mut pair, mut sock, left, wait, _) = sight(&f, "from");
            let asked = asks(&pair, sock.has_room(), sock.holds(), left != "no");
            let ask = |name: &str, event| if f[&format!("asks.{name}")] == "TRUE" { event } else { 0 };
            let watched =
                (f["asks.watched"] == "TRUE").then_some(ask("read", libc::POLLIN) | ask("write", libc::POLLOUT));
            assert_eq!(asked, watched, "poll is asked otherwise in {line}");

            let (mut left, mut wait) = (since(&left, TCP_TIMEOUT), since(&wait, FIN_WAIT));
            let closing = f["from.closing"] == "TRUE";
            let fate = match f["at"].as_str() {
                "idle" => carry(&mut pair, &mut sock, &mut left, &mut wait, NOW, closing),
                "take" => take(&mut pair, &mut sock).unwrap_or(Fate::Rest),
                "give" => {
                    give(&mut pair, &mut sock);
                    Fate::Rest
                }
                "end" => {
                    end(&mut pair, &sock);
                    Fate::Rest
                }
                "judge" => judge(&pair, &sock, &mut left, &mut wait, NOW, closing),
                at => panic!("the model has no step {at}"),
            };
            // step resets the socket of a connection that carry aborts.
            let phase = match fate {
                Fate::Rest => "open",
                Fate::Close => "dead",
                Fate::Abort => {
                    sock.abort();
                    "dead"
                }
            };
            let after = (pair, sock, named(left, TCP_TIMEOUT).into(), named(wait, FIN_WAIT).into(), phase.into());
            assert_eq!(after, sight(&f, "to"), "the code goes otherwise from {line}");
        }
    }
}

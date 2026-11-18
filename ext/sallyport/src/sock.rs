//! What carry may ask of a TCP socket, and what it may take for granted.
//!
//! smoltcp's socket has eleven states, and carry needs to know two things
//! of each direction. Each method here says what carry relies on. Where
//! smoltcp does not give that by itself, the method says what makes it so,
//! and which test holds smoltcp to it.

use smoltcp::socket::tcp;
use std::collections::VecDeque;

// The module "sock" is this contract as the model "conn" has it. The
// lines of the module are here and beside the calls below.
//
// TLA-sock> \* This is one connection's socket as sock.rs lets the stack see it, with
// TLA-sock> \* what the peer and time may do to it. A state of the socket is a record
// TLA-sock> \* with these fields.
// TLA-sock> \*   pending  the handshake is not over
// TLA-sock> \*   up       the stream to the peer is "open", "ending" (our FIN is
// TLA-sock> \*            queued) or "ended"
// TLA-sock> \*   down     the peer may still send
// TLA-sock> \*   tx       the bytes that the socket holds and the peer has not
// TLA-sock> \*            acknowledged
// TLA-sock> \*   rx       the bytes that the socket holds for Ruby
// TLA-sock> \*   owed     what the socket has yet to send that is no data, which is
// TLA-sock> \*            "none", "ack" or "rst"
// TLA-sock> \*   cut      the connection is reset or timed out, by either side
// TLA-sock> \*   fin      the peer's FIN has arrived
// TLA-sock> \*   gone     the peer reset the connection, or it is silent for good
// TLA-sock> \*   quota    the bytes that the peer may still send
// TLA-sock> EXTENDS Naturals
// TLA-sock> CONSTANTS TxCap, RxCap, Budget, Fault
// TLA-sock> When(cond, x) == IF cond THEN {x} ELSE {}
// TLA-sock> New == [pending |-> TRUE, up |-> "open", down |-> TRUE, tx |-> 0, rx |-> 0, owed |-> "none",
// TLA-sock>         cut |-> FALSE, fin |-> FALSE, gone |-> FALSE, quota |-> Budget]
// TLA-sock> \* A connection that is cut has no stream left, and what the socket held
// TLA-sock> \* for the peer is gone.
// TLA-sock> Cut(k) == [k EXCEPT !.pending = FALSE, !.up = "ended", !.down = FALSE, !.cut = TRUE, !.tx = 0]
// TLA-sock> \* The peer may finish the handshake or refuse it. Then it may send,
// TLA-sock> \* acknowledge, end its stream and reset the connection, in any order.
// TLA-sock> \* Each of these is the set of the states that a packet of the peer leads
// TLA-sock> \* to, and it is empty when the peer cannot send that packet.
// TLA-sock> PeerAnswers(k) == When(k.pending /\ ~k.gone, [k EXCEPT !.pending = FALSE])
// TLA-sock> PeerRefuses(k) == When(k.pending /\ ~k.gone, [Cut(k) EXCEPT !.gone = TRUE])
// TLA-sock> PeerSends(k) == When(~k.pending /\ ~k.gone /\ k.down /\ k.rx < RxCap /\ k.quota > 0,
// TLA-sock>                      [k EXCEPT !.rx = @ + 1, !.quota = @ - 1])
// TLA-sock> PeerAcks(k) == When(~k.gone /\ k.tx > 0, [k EXCEPT !.tx = @ - 1])
// TLA-sock> \* Our FIN follows our data, so it is acknowledged after the data.
// TLA-sock> PeerAcksFin(k) == When(~k.gone /\ k.tx = 0 /\ k.up = "ending", [k EXCEPT !.up = "ended"])
// TLA-sock> \* The socket takes the peer's FIN only when it has taken all that the
// TLA-sock> \* peer sent before it. smoltcp does not see to that, so Stack::receive
// TLA-sock> \* gives it each FIN in a packet of its own.
// TLA-sock> PeerFins(k) == When(~k.pending /\ ~k.gone /\ k.down,
// TLA-sock>                     [k EXCEPT !.down = FALSE, !.fin = TRUE, !.owed = "ack"])
// TLA-sock> \* A reset leaves what was received for Ruby to read, and leaves nothing
// TLA-sock> \* to send.
// TLA-sock> PeerResets(k) == When(~k.pending /\ ~k.gone /\ ~k.cut,
// TLA-sock>                       [Cut(k) EXCEPT !.gone = TRUE, !.owed = "none"])
// TLA-sock> Packet(k) == PeerAnswers(k) \cup PeerRefuses(k) \cup PeerSends(k) \cup PeerAcks(k)
// TLA-sock>              \cup PeerAcksFin(k) \cup PeerFins(k) \cup PeerResets(k)
// TLA-sock> \* The peer may also go silent for good, at any time.
// TLA-sock> Silence(k) == When(~k.gone, [k EXCEPT !.gone = TRUE])
// TLA-sock> \* smoltcp cuts a connection that has taken nothing from its peer for
// TLA-sock> \* TCP_TIMEOUT, and resets the peer. It counts the silence whether or not
// TLA-sock> \* anything waits for an answer. So the socket asks a quiet peer to
// TLA-sock> \* answer, with set_keep_alive, and it hears a peer that is there. The
// TLA-sock> \* stack's clock does not count the time that the thread stood still, so
// TLA-sock> \* the socket has asked by then. And with a window that has no scale, a
// TLA-sock> \* peer that has sent past the end that smoltcp has on record is heard
// TLA-sock> \* when it sends those bytes again.
// TLA-sock> TimesOut(k) == When(~(k.up = "ended" /\ ~k.down) /\ (k.gone \/ Fault = "no keep-alive"),
// TLA-sock>                     [Cut(k) EXCEPT !.owed = "rst"])
// TLA-sock> \* tcp::Socket::abort. A socket that is cut already has no peer to reset.
// TLA-sock> Abort(k) == [Cut(k) EXCEPT !.owed = IF k.cut THEN @ ELSE "rst"]

/// The stream to the peer, as carry sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Up {
    /// The socket takes bytes for the peer.
    Open,
    /// Our FIN is queued, and the peer has yet to acknowledge it.
    Ending,
    /// The peer has acknowledged our FIN, or the connection was reset or
    /// timed out. Nothing more is sent but a last ACK or a reset.
    Ended,
}

/// A handshake, as step sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Opening {
    /// The handshake is not over.
    Pending,
    /// The connection is established, or was and has gone further.
    Done,
    /// The peer refused or reset the connection, or it timed out.
    Failed,
}

/// What moves bytes into the socket or out of it says how many it moved.
pub trait Moved {
    fn bytes(&self) -> usize;
}

/// One connection's socket, with the bytes that were taken out of it for
/// Ruby before smoltcp could clear them.
pub struct Sock<'a, 'b> {
    s: &'a mut tcp::Socket<'b>,
    tail: &'a mut VecDeque<u8>,
}

impl<'a, 'b> Sock<'a, 'b> {
    // TLA-sock> \* Sock::new. The socket keeps what it holds for Ruby until Ruby is given
    // TLA-sock> \* it. smoltcp alone would clear it ten seconds after both streams have
    // TLA-sock> \* ended, and this is that fault.
    // TLA-sock> Forgets(k) == When(Fault = "no tail" /\ k.up = "ended" /\ ~k.down /\ k.rx > 0, [k EXCEPT !.rx = 0])
    /// The socket keeps what it holds for Ruby until Ruby is given it.
    /// smoltcp clears a socket when it has been in TIME-WAIT for ten
    /// seconds, and its receive buffer with it. So those bytes are taken
    /// out of the buffer as soon as both streams have ended, and are
    /// given from the tail (`what_ruby_has_not_read_outlasts_time_wait`).
    pub fn new(s: &'a mut tcp::Socket<'b>, tail: &'a mut VecDeque<u8>) -> Self {
        if s.state() == tcp::State::TimeWait {
            while s.can_recv() {
                let _ = s.recv(|buf| {
                    tail.extend(buf.iter());
                    (buf.len(), ())
                });
            }
        }
        Sock { s, tail }
    }

    /// Says how far the stream to the peer has come. It only goes on:
    /// from open to ending when carry ends it, and to ended when the peer
    /// acknowledges that or the connection is cut.
    pub fn up(&self) -> Up {
        match self.s.state() {
            tcp::State::Established | tcp::State::CloseWait => Up::Open,
            tcp::State::FinWait1 | tcp::State::Closing | tcp::State::LastAck => Up::Ending,
            _ => Up::Ended,
        }
    }

    /// Says whether the peer may still send. It may not once its FIN has
    /// arrived, or once the connection is cut. The FIN is taken only
    /// after every byte before it: Stack::receive gives smoltcp a FIN
    /// apart from its data to make that so
    /// (`a_fin_is_not_taken_with_a_segment_that_the_window_cut`).
    pub fn down_open(&self) -> bool {
        matches!(self.s.state(), tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2)
    }

    // TLA-sock> \* Sock::has_room and Sock::fill
    // TLA-sock> HasRoom(k) == k.up = "open" /\ k.tx < TxCap
    // TLA-sock> Room(k) == TxCap - k.tx
    // TLA-sock> Filled(k, n) == [k EXCEPT !.tx = @ + n]
    /// Says whether the socket has room for bytes from Ruby now.
    pub fn has_room(&self) -> bool {
        self.s.can_send()
    }

    /// Lets `read` put bytes for the peer into the socket's buffer, and
    /// returns what `read` found. Returns nothing if the socket takes no
    /// bytes, which carry rules out by asking for room first.
    pub fn fill<R: Moved>(&mut self, read: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let filled = |buf: &mut [u8]| {
            let found = read(buf);
            (found.bytes(), found)
        };
        self.s.send(filled).ok()
    }

    // TLA-sock> \* Sock::all_acknowledged and Sock::end
    // TLA-sock> AllAcked(k) == k.tx = 0
    // TLA-sock> End(k) == [k EXCEPT !.up = "ending"]
    /// Says whether the peer has acknowledged all that the socket took.
    pub fn all_acknowledged(&self) -> bool {
        self.s.send_queue() == 0
    }

    /// Ends the stream to the peer. carry does this only when the peer
    /// has acknowledged everything, because smoltcp does not send a FIN
    /// well behind data that a shut window holds back
    /// (`a_fin_does_not_ride_on_the_probe_of_a_shut_window`,
    /// `a_fin_waits_for_a_peer_that_ended_first_to_take_the_data`).
    pub fn end(&mut self) {
        self.s.close();
    }

    // TLA-sock> \* Sock::holds and Sock::drain
    // TLA-sock> Holds(k) == k.rx > 0
    // TLA-sock> Drained(k, n) == [k EXCEPT !.rx = @ - n]
    /// Says whether the socket holds bytes for Ruby.
    pub fn holds(&self) -> bool {
        !self.tail.is_empty() || self.s.can_recv()
    }

    /// Lets `write` take bytes for Ruby, the oldest first, and returns
    /// what `write` found. Returns nothing if the socket holds no bytes,
    /// which carry rules out by asking first.
    pub fn drain<R: Moved>(&mut self, write: impl FnOnce(&[u8]) -> R) -> Option<R> {
        if !self.tail.is_empty() {
            let found = write(self.tail.as_slices().0);
            self.tail.drain(..found.bytes());
            return Some(found);
        }
        let drained = |buf: &mut [u8]| {
            let found = write(buf);
            (found.bytes(), found)
        };
        self.s.recv(drained).ok()
    }

    // TLA-sock> \* Sock::opening
    // TLA-sock> Opening(k) == IF k.pending THEN "pending" ELSE IF k.cut THEN "failed" ELSE "done"
    /// Says how the handshake of a socket stands. A socket that listens
    /// and has seen no SYN is pending too. smoltcp puts a socket that
    /// listened back in LISTEN when its handshake is reset, and
    /// Stack::unlisten removes such a socket before step sees it
    /// (`a_handshake_that_its_peer_resets_leaves_no_socket`).
    pub fn opening(s: &tcp::Socket) -> Opening {
        match s.state() {
            tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived => Opening::Pending,
            tcp::State::Closed => Opening::Failed,
            _ => Opening::Done,
        }
    }

    // TLA-sock> \* Sock::silent. A socket that was reset is silent once the reset has left.
    // TLA-sock> Silent(k) == k.cut /\ k.owed = "none"
    /// Says whether a socket that is closed has sent all that it owed.
    /// smoltcp forgets the peer once it has no more to send it. A socket
    /// that waits out TIME-WAIT is never silent in this sense: the peer's
    /// FIN may still be owed an ACK.
    pub fn silent(s: &tcp::Socket) -> bool {
        s.state() == tcp::State::Closed && s.remote_endpoint().is_none()
    }

    /// Says what poll is to be asked for a socket: whether it has room for
    /// bytes from Ruby, and whether it holds bytes for Ruby.
    pub fn asks(s: &tcp::Socket, tail: &VecDeque<u8>) -> (bool, bool) {
        (s.can_send(), s.can_recv() || !tail.is_empty())
    }
}

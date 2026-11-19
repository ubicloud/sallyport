//! This file says what the stack may ask of a TCP socket, and what it
//! may take for granted.
//!
//! smoltcp's socket has eleven states, and carry needs to know two things
//! of each direction. Each method here says what the stack relies on.
//! Where smoltcp does not give that by itself, the method says what makes
//! it so, and which test holds smoltcp to it. Nothing else in the library
//! makes a socket, or names a state of one.

use smoltcp::iface::Context;
use smoltcp::socket::tcp;
use smoltcp::time::Duration as SDuration;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A Socket is smoltcp's socket for one TCP connection.
pub type Socket = tcp::Socket<'static>;

/// A socket holds this many bytes that Ruby wrote, until the peer has
/// acknowledged them.
pub const SEND_BUF: usize = 256 * 1024;
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
pub const RECV_BUF: usize = 65535;
/// A connection is dead when its peer has sent nothing for this long.
/// smoltcp counts the silence whether or not anything waits to be
/// acknowledged, so a connection has to ask a quiet peer to answer.
pub const TCP_TIMEOUT: Duration = Duration::from_secs(300);
/// A connection asks its peer for an ACK when the peer has been quiet for
/// this long.
const KEEP_ALIVE: Duration = Duration::from_secs(75);
/// The retransmission timer waits this long at the least for a segment
/// to be acknowledged. smoltcp's waits a second by default, as RFC 6298
/// advises, and that of Linux waits 200 ms. A peer may delay an ACK for
/// nearly as long, so a shorter wait would send again what was not lost.
const MIN_RTO: Duration = Duration::from_millis(200);

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
// TLA-sock> \* Stack::poll has smoltcp send what a socket owes. That is one packet,
// TLA-sock> \* and the first round of a poll sends it, whatever the other sockets
// TLA-sock> \* have to send. The socket delays none of it: Sock::make has it
// TLA-sock> \* acknowledge at once.
// TLA-sock> Sent(k) == [k EXCEPT !.owed = "none"]

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

/// carry makes these calls on a socket, and no others. Sock has them for
/// smoltcp's socket. A test in conn.rs has them for a socket that is the
/// record of the module "sock", and so holds carry to the model.
pub trait SockCalls {
    fn up(&self) -> Up;
    fn down_open(&self) -> bool;
    fn has_room(&self) -> bool;
    fn fill<R: Moved>(&mut self, read: impl FnOnce(&mut [u8]) -> R) -> Option<R>;
    fn all_acknowledged(&self) -> bool;
    fn end(&mut self);
    fn holds(&self) -> bool;
    fn drain<R: Moved>(&mut self, write: impl FnOnce(&[u8]) -> R) -> Option<R>;
}

/// One connection's socket, with the bytes that were taken out of it for
/// Ruby before smoltcp could clear them.
pub struct Sock<'a> {
    s: &'a mut Socket,
    tail: &'a mut VecDeque<u8>,
}

impl<'a> Sock<'a> {
    /// Makes a socket with the settings that this contract rests on.
    fn make() -> Socket {
        let mut s = Socket::new(tcp::SocketBuffer::new(vec![0; RECV_BUF]), tcp::SocketBuffer::new(vec![0; SEND_BUF]));
        s.set_timeout(Some(SDuration::from_millis(TCP_TIMEOUT.as_millis() as u64)));
        s.set_keep_alive(Some(SDuration::from_millis(KEEP_ALIVE.as_millis() as u64)));
        // The socket pair has already gathered what Ruby wrote, and a key
        // typed into an interactive session must not wait for an ACK.
        s.set_nagle_enabled(false);
        // smoltcp has no congestion control unless one is chosen: it sends
        // as much as the peer's window takes, whatever the path can carry.
        s.set_congestion_control(tcp::CongestionControl::Cubic);
        s.set_min_rto(SDuration::from_millis(MIN_RTO.as_millis() as u64));
        // The socket sends an ACK in the turn in which it comes to owe
        // it. smoltcp would else delay the ACK for up to 10 ms, and the
        // socket of a connection that has ended would have to stay as
        // long, to send its last one. The loop has the sockets send once
        // in a turn, so one ACK answers all that the turn took in
        // (`a_connection_that_ends_sends_its_last_ack_in_the_same_turn`).
        s.set_ack_delay(None);
        s
    }

    /// Makes a socket that begins a connection to a port of a peer, from
    /// a local port. smoltcp refuses the unspecified address, and none is
    /// made then.
    pub fn connecting(cx: &mut Context, addr: IpAddr, port: u16, local: u16) -> Option<Socket> {
        let mut s = Sock::make();
        let from = IpListenEndpoint { addr: None, port: local };
        s.connect(cx, (IpAddress::from(addr), port), from).ok()?;
        Some(s)
    }

    /// Makes a socket that listens on a port. It takes one connection:
    /// smoltcp keeps no queue of them.
    pub fn listening(port: u16) -> Option<Socket> {
        let mut s = Sock::make();
        s.listen(port).ok()?;
        Some(s)
    }

    /// Says whether a socket listens still. One that has taken a SYN does
    /// not, unless its peer reset the handshake: smoltcp has such a
    /// socket listen again
    /// (`a_socket_whose_handshake_was_reset_takes_no_other_syn`).
    pub fn listens(s: &Socket) -> bool {
        s.state() == tcp::State::Listen
    }

    /// Says whether a socket has the connection between these two ends. A
    /// socket that listens has none.
    pub fn has(s: &Socket, from: SocketAddr, to: SocketAddr) -> bool {
        !Sock::listens(s)
            && s.remote_endpoint() == Some(IpEndpoint::from(from))
            && s.local_endpoint() == Some(IpEndpoint::from(to))
    }

    /// Returns the peer's end of a connection. A socket that has yet to
    /// take a SYN has none, and neither has one that is cut and has sent
    /// what it owed.
    pub fn peer(s: &Socket) -> Option<IpEndpoint> {
        s.remote_endpoint()
    }

    // TLA-sock> \* Sock::abort. A socket that is cut already has no peer to reset.
    // TLA-sock> Abort(k) == [Cut(k) EXCEPT !.owed = IF k.cut THEN @ ELSE "rst"]
    /// Cuts the connection, and has the socket reset the peer.
    pub fn abort(s: &mut Socket) {
        s.abort();
    }

    /// Says whether a socket has a packet to send now. Of a socket whose
    /// connection has ended, that is the reset or the last ACK that it
    /// owes the peer. The copy of smoltcp in vendor has sends_now for
    /// this, and the line of the model that goes with it.
    pub fn owes(s: &Socket, cx: &mut Context) -> bool {
        s.sends_now(cx)
    }

    /// Describes a socket in a few words, for a person: its two ends, its
    /// state as smoltcp names it, and how many bytes it holds each way.
    /// `tail` is how many bytes for Ruby were taken out of it.
    pub fn describe(s: &Socket, tail: usize) -> String {
        let end = |end: Option<IpEndpoint>| end.map_or("-".into(), |end| end.to_string());
        format!(
            "{} to {}: {}, {} bytes to send and {} to give Ruby",
            end(s.local_endpoint()),
            end(s.remote_endpoint()),
            s.state(),
            s.send_queue(),
            s.recv_queue() + tail,
        )
    }

    // TLA-sock> \* Sock::new. The socket keeps what it holds for Ruby until Ruby is given
    // TLA-sock> \* it. smoltcp alone would clear it ten seconds after both streams have
    // TLA-sock> \* ended, and this is that fault.
    // TLA-sock> Forgets(k) == When(Fault = "no tail" /\ k.up = "ended" /\ ~k.down /\ k.rx > 0, [k EXCEPT !.rx = 0])
    /// The socket keeps what it holds for Ruby until Ruby is given it.
    /// smoltcp clears a socket when it has been in TIME-WAIT for ten
    /// seconds, and its receive buffer with it. So those bytes are taken
    /// out of the buffer as soon as both streams have ended, and are
    /// given from the tail (`what_ruby_has_not_read_outlasts_time_wait`).
    pub fn new(s: &'a mut Socket, tail: &'a mut VecDeque<u8>) -> Self {
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

    // TLA-sock> \* Sock::opening
    // TLA-sock> Opening(k) == IF k.pending THEN "pending" ELSE IF k.cut THEN "failed" ELSE "done"
    /// Says how the handshake of a socket stands. A socket that listens
    /// and has seen no SYN is pending too. smoltcp puts a socket that
    /// listened back in LISTEN when its handshake is reset, and
    /// Stack::unlisten removes such a socket before step sees it
    /// (`a_handshake_that_its_peer_resets_leaves_no_socket`).
    pub fn opening(s: &Socket) -> Opening {
        match s.state() {
            tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived => Opening::Pending,
            tcp::State::Closed => Opening::Failed,
            _ => Opening::Done,
        }
    }

    /// Says what poll is to be asked for a socket: whether it has room for
    /// bytes from Ruby, and whether it holds bytes for Ruby.
    pub fn asks(s: &Socket, tail: &VecDeque<u8>) -> (bool, bool) {
        (s.can_send(), s.can_recv() || !tail.is_empty())
    }
}

impl SockCalls for Sock<'_> {
    /// Says how far the stream to the peer has come. It only goes on:
    /// from open to ending when carry ends it, and to ended when the peer
    /// acknowledges that or the connection is cut.
    fn up(&self) -> Up {
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
    fn down_open(&self) -> bool {
        matches!(self.s.state(), tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2)
    }

    // TLA-sock> \* Sock::has_room and Sock::fill
    // TLA-sock> HasRoom(k) == k.up = "open" /\ k.tx < TxCap
    // TLA-sock> Room(k) == TxCap - k.tx
    // TLA-sock> Filled(k, n) == [k EXCEPT !.tx = @ + n]
    /// Says whether the socket has room for bytes from Ruby now.
    fn has_room(&self) -> bool {
        self.s.can_send()
    }

    /// Lets `read` put bytes for the peer into the socket's buffer, and
    /// returns what `read` found. Returns nothing if the socket takes no
    /// bytes, which carry rules out by asking for room first.
    fn fill<R: Moved>(&mut self, read: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
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
    fn all_acknowledged(&self) -> bool {
        self.s.send_queue() == 0
    }

    /// Ends the stream to the peer. carry does this only when the peer
    /// has acknowledged everything, because smoltcp does not send a FIN
    /// well behind data that a shut window holds back
    /// (`a_fin_does_not_ride_on_the_probe_of_a_shut_window`,
    /// `a_fin_waits_for_a_peer_that_ended_first_to_take_the_data`).
    fn end(&mut self) {
        self.s.close();
    }

    // TLA-sock> \* Sock::holds and Sock::drain
    // TLA-sock> Holds(k) == k.rx > 0
    // TLA-sock> Drained(k, n) == [k EXCEPT !.rx = @ - n]
    /// Says whether the socket holds bytes for Ruby.
    fn holds(&self) -> bool {
        !self.tail.is_empty() || self.s.can_recv()
    }

    /// Lets `write` take bytes for Ruby, the oldest first, and returns
    /// what `write` found. Returns nothing if the socket holds no bytes,
    /// which carry rules out by asking first.
    fn drain<R: Moved>(&mut self, write: impl FnOnce(&[u8]) -> R) -> Option<R> {
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
}

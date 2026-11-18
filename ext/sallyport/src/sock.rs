//! What carry may ask of a TCP socket, and what it may take for granted.
//!
//! smoltcp's socket has eleven states, and carry needs to know two things
//! of each direction. Each method here says what carry relies on. Where
//! smoltcp does not give that by itself, the method says what makes it so,
//! and which test holds smoltcp to it. The model "conn" has a socket of
//! this shape and of no other.

use smoltcp::socket::tcp;
use std::collections::VecDeque;

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

/// One connection's socket, with the bytes that were taken out of it for
/// Ruby before smoltcp could clear them.
pub struct Sock<'a, 'b> {
    s: &'a mut tcp::Socket<'b>,
    tail: &'a mut VecDeque<u8>,
}

impl<'a, 'b> Sock<'a, 'b> {
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

    /// Says whether the socket has room for bytes from Ruby now.
    pub fn has_room(&self) -> bool {
        self.s.can_send()
    }

    /// Lets `read` put bytes for the peer into the socket's buffer, and
    /// returns what `read` returned: how many bytes, or what stopped it.
    pub fn fill(&mut self, mut read: impl FnMut(&mut [u8]) -> isize) -> isize {
        self.s
            .send(|buf| {
                let n = read(buf);
                (n.max(0) as usize, n)
            })
            .unwrap_or(0)
    }

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

    /// Says whether the socket holds bytes for Ruby.
    pub fn holds(&self) -> bool {
        !self.tail.is_empty() || self.s.can_recv()
    }

    /// Lets `write` take bytes for Ruby, the oldest first, and returns
    /// what `write` returned: how many bytes it took, or what stopped it.
    pub fn drain(&mut self, mut write: impl FnMut(&[u8]) -> isize) -> isize {
        if !self.tail.is_empty() {
            let n = write(self.tail.as_slices().0);
            self.tail.drain(..n.max(0) as usize);
            return n;
        }
        self.s
            .recv(|buf| {
                let n = write(buf);
                (n.max(0) as usize, n)
            })
            .unwrap_or(0)
    }

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

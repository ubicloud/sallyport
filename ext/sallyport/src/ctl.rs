//! This file says what the stack may ask of a listener's socket pair, and
//! what it may take for granted.
//!
//! Ruby's Listener holds one end of the pair and the stack holds the
//! other. The pair keeps messages apart. The stack sends a status, and
//! then each connection as a message that carries the connection's
//! descriptor. Ruby answers each connection that it takes with a message
//! of its own. Each call here says what the stack relies on, and the
//! tests below hold Linux to it.

use crate::sys;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// A listener's backlog is no more than this. With the socket buffer that
/// Linux gives a pair by default, the pair holds this many messages each
/// way, and the status with them
/// (`the_pair_holds_the_messages_of_the_largest_backlog`). So no
/// connection waits for room in the pair there. The buffer is a setting
/// of the system, net.core.wmem_default, and where it is small a
/// connection may wait
/// (`a_pair_that_is_full_takes_no_more_until_ruby_takes_a_connection`).
pub const MAX_BACKLOG: usize = 128;

/// What became of a connection that the stack sent.
#[derive(Debug, PartialEq)]
pub enum Sent {
    /// The pair took it.
    Ok,
    /// The pair has no room for it until Ruby takes a connection.
    Full,
    /// Ruby has closed the listener.
    Gone,
}

// The module "ctl" is this contract as the model "listen" has it. The
// lines of the module are here and beside the calls below, and Ruby's
// part is in listener.rb.
//
// TLA-ctl> \* This is a listener's socket pair as ctl.rs lets the stack see it, with
// TLA-ctl> \* what Ruby may do with its end. A state of the pair is a record with
// TLA-ctl> \* these fields. The kernel keeps the first three, and our end keeps the
// TLA-ctl> \* last.
// TLA-ctl> \*   open        Ruby has not closed the listener
// TLA-ctl> \*   queued      the connections that Ruby was sent and has yet to take
// TLA-ctl> \*   answers     the answers of Ruby that the stack has yet to read
// TLA-ctl> \*   unaccepted  Ctl::unaccepted
// TLA-ctl> EXTENDS Naturals
// TLA-ctl> CONSTANT Holds  \* how many connections the pair holds for Ruby
// TLA-ctl> When(cond, x) == IF cond THEN {x} ELSE {}
// TLA-ctl> New == [open |-> TRUE, queued |-> 0, answers |-> 0, unaccepted |-> 0]
// TLA-ctl> \* Ruby may close the listener at any time.
// TLA-ctl> Closes(c) == When(c.open, [c EXCEPT !.open = FALSE])

/// A Ctl is our end of a listener's pair, and the count of what Ruby has
/// yet to accept.
pub struct Ctl {
    fd: OwnedFd,
    unaccepted: usize,
}

impl Ctl {
    pub fn new(fd: OwnedFd) -> Ctl {
        Ctl { fd, unaccepted: 0 }
    }

    /// Sends the status that is the first message of a listener, and
    /// says whether the pair took it.
    pub fn say(&self, status: u8) -> bool {
        sys::send(self.fd.as_raw_fd(), &[status]) == 1
    }

    // TLA-ctl> \* Ctl::send, on a pair that Ruby has not closed. The pair takes a
    // TLA-ctl> \* connection unless it is full.
    // TLA-ctl> Full(c) == c.queued >= Holds
    // TLA-ctl> Sent(c) == [c EXCEPT !.queued = @ + 1, !.unaccepted = @ + 1]
    /// Sends Ruby a connection: the words that name its peer, and Ruby's
    /// end of the connection's pair. Says what became of it, and counts
    /// it if the pair took it. A pair that is full takes it once Ruby has
    /// taken a connection
    /// (`a_pair_that_is_full_takes_no_more_until_ruby_takes_a_connection`),
    /// and a pair takes none once Ruby has closed the listener
    /// (`a_listener_that_ruby_closed_has_ended`). If Ruby closes the
    /// listener and has not taken the connection, the kernel closes that
    /// end, and the connection is then one whose Ruby has closed
    /// (`a_connection_that_ruby_never_took_is_closed_with_the_listener`).
    pub fn send(&mut self, peer: &str, theirs: &OwnedFd) -> Sent {
        match sys::send_fd(self.fd.as_raw_fd(), peer.as_bytes(), theirs.as_raw_fd()) {
            sys::AGAIN => Sent::Full,
            n if n >= 0 => {
                self.unaccepted += 1;
                Sent::Ok
            }
            _ => Sent::Gone,
        }
    }

    // TLA-ctl> \* Ctl::credit
    // TLA-ctl> Credited(c) == [c EXCEPT !.unaccepted = @ - c.answers, !.answers = 0]
    /// Reads the answers that Ruby has sent, and takes them from the
    /// count. Each answer is a message of its own, however many wait
    /// (`each_answer_is_a_message_of_its_own`).
    pub fn credit(&mut self) {
        while sys::read(self.fd.as_raw_fd(), &mut [0; 16]) > 0 {
            self.unaccepted = self.unaccepted.saturating_sub(1);
        }
    }

    /// Returns how many connections Ruby was sent and had not accepted
    /// when the answers were last read.
    pub fn unaccepted(&self) -> usize {
        self.unaccepted
    }

    // TLA-ctl> \* Ctl::ended
    // TLA-ctl> Ended(c) == ~c.open
    /// Says whether Ruby has closed the listener. The pair then takes no
    /// more (`a_listener_that_ruby_closed_has_ended`).
    pub fn ended(&self) -> bool {
        sys::ended(self.fd.as_raw_fd())
    }

    /// Returns our end as poll takes it. poll reports that there is
    /// something to read when Ruby has answered, and when it has closed
    /// the listener.
    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair::{Hangup, Pair, PairCalls, Took};
    use std::os::unix::net::UnixDatagram;

    /// Makes a listener's pair, and returns our end and Ruby's end. std
    /// has no type for a socket of the pair's kind, and UnixDatagram sends
    /// and receives a message on one well enough.
    fn ctl() -> (Ctl, UnixDatagram) {
        let (ours, theirs) = sys::socketpair(libc::SOCK_SEQPACKET).unwrap();
        let ruby = UnixDatagram::from(theirs);
        ruby.set_nonblocking(true).unwrap();
        (Ctl::new(ours), ruby)
    }

    /// Sends a connection on the pair. Returns what became of it, and our
    /// end of the connection.
    fn connection(ours: &mut Ctl) -> (Sent, Pair) {
        let (mine, theirs) = sys::socketpair(libc::SOCK_STREAM).unwrap();
        // The longest words that name a peer.
        (ours.send("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535", &theirs), Pair::new(mine))
    }

    #[test]
    fn the_pair_holds_the_messages_of_the_largest_backlog() {
        let (mut ours, ruby) = ctl();
        assert!(ours.say(0));
        let sent: Vec<(Sent, Pair)> = (0..MAX_BACKLOG).map(|_| connection(&mut ours)).collect();
        assert!(sent.iter().all(|(sent, _)| *sent == Sent::Ok) && ours.unaccepted() == MAX_BACKLOG);
        for _ in 0..MAX_BACKLOG {
            ruby.send(&[0]).unwrap();
        }
        ours.credit();
        assert_eq!(ours.unaccepted(), 0);
    }

    #[test]
    fn a_pair_that_is_full_takes_no_more_until_ruby_takes_a_connection() {
        let (mut ours, ruby) = ctl();
        let mut held = Vec::new();
        loop {
            let (sent, mine) = connection(&mut ours);
            held.push(mine);
            if sent != Sent::Ok {
                assert_eq!(sent, Sent::Full);
                break;
            }
        }
        assert_eq!(ours.unaccepted(), held.len() - 1, "a connection that the pair did not take is not counted");
        ruby.recv(&mut [0; 64]).unwrap();
        assert_eq!(connection(&mut ours).0, Sent::Ok);
    }

    #[test]
    fn each_answer_is_a_message_of_its_own() {
        let (mut ours, ruby) = ctl();
        let _sent: Vec<(Sent, Pair)> = (0..4).map(|_| connection(&mut ours)).collect();
        ours.credit();
        assert_eq!(ours.unaccepted(), 4);
        for _ in 0..3 {
            ruby.send(&[0]).unwrap();
        }
        ours.credit();
        assert_eq!(ours.unaccepted(), 1);
    }

    #[test]
    fn a_listener_that_ruby_closed_has_ended() {
        let (mut ours, ruby) = ctl();
        assert!(!ours.ended() && connection(&mut ours).0 == Sent::Ok && !ours.ended());
        drop(ruby);
        assert!(ours.ended() && connection(&mut ours).0 == Sent::Gone && ours.unaccepted() == 1);
    }

    #[test]
    fn a_connection_that_ruby_never_took_is_closed_with_the_listener() {
        let (mut ours, ruby) = ctl();
        let (sent, mut mine) = connection(&mut ours);
        assert!(sent == Sent::Ok && mine.hangup() == Hangup::No);
        drop(ruby);
        assert!(mine.hangup() == Hangup::Yes && mine.read(&mut [0; 16]) == Took::End);
    }
}

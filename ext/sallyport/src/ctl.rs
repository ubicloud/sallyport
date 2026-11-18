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

/// A listener's backlog is no more than this, so that neither side ever
/// waits to send a message: the pair holds this many each way, and the
/// status with them (`the_pair_holds_the_messages_of_the_largest_backlog`).
pub const MAX_BACKLOG: usize = 128;

/// A Ctl is our end of a listener's pair.
pub struct Ctl {
    fd: OwnedFd,
}

impl Ctl {
    pub fn new(fd: OwnedFd) -> Ctl {
        Ctl { fd }
    }

    /// Sends the status that is the first message of a listener.
    pub fn say(&self, status: u8) {
        sys::send(self.fd.as_raw_fd(), &[status]);
    }

    /// Sends Ruby a connection: the words that name its peer, and Ruby's
    /// end of the connection's pair. Returns whether the pair took it.
    /// The pair has room for it, so it takes it unless Ruby has closed
    /// the listener (`a_listener_that_ruby_closed_has_ended`). If Ruby
    /// closes the listener and has not taken the connection, the kernel
    /// closes that end, and the connection is then one whose Ruby has
    /// closed
    /// (`a_connection_that_ruby_never_took_is_closed_with_the_listener`).
    pub fn send(&self, peer: &str, theirs: &OwnedFd) -> bool {
        sys::send_fd(self.fd.as_raw_fd(), peer.as_bytes(), theirs.as_raw_fd()) >= 0
    }

    /// Takes the answers that Ruby has sent, and returns how many there
    /// were. Each is a message of its own, however many wait
    /// (`each_answer_is_a_message_of_its_own`).
    pub fn answers(&self) -> usize {
        let mut answers = 0;
        while sys::read(self.fd.as_raw_fd(), &mut [0; 16]) > 0 {
            answers += 1;
        }
        answers
    }

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
    use crate::pair::{Hangup, Pair, Took};
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

    /// Sends a connection on the pair. Returns whether the pair took it,
    /// and our end of the connection.
    fn connection(ours: &Ctl) -> (bool, Pair) {
        let (mine, theirs) = sys::socketpair(libc::SOCK_STREAM).unwrap();
        // The longest words that name a peer.
        (ours.send("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535", &theirs), Pair::new(mine))
    }

    #[test]
    fn the_pair_holds_the_messages_of_the_largest_backlog() {
        let (ours, ruby) = ctl();
        ours.say(0);
        let sent: Vec<(bool, Pair)> = (0..MAX_BACKLOG).map(|_| connection(&ours)).collect();
        assert!(sent.iter().all(|(sent, _)| *sent));
        for _ in 0..MAX_BACKLOG {
            ruby.send(&[0]).unwrap();
        }
        assert_eq!(ours.answers(), MAX_BACKLOG);
    }

    #[test]
    fn each_answer_is_a_message_of_its_own() {
        let (ours, ruby) = ctl();
        assert_eq!(ours.answers(), 0);
        for _ in 0..3 {
            ruby.send(&[0]).unwrap();
        }
        assert!(ours.answers() == 3 && ours.answers() == 0);
    }

    #[test]
    fn a_listener_that_ruby_closed_has_ended() {
        let (ours, ruby) = ctl();
        assert!(!ours.ended() && connection(&ours).0 && !ours.ended());
        drop(ruby);
        assert!(ours.ended() && !connection(&ours).0);
    }

    #[test]
    fn a_connection_that_ruby_never_took_is_closed_with_the_listener() {
        let (ours, ruby) = ctl();
        let (sent, mut mine) = connection(&ours);
        assert!(sent && mine.hangup() == Hangup::No);
        drop(ruby);
        assert!(mine.hangup() == Hangup::Yes && mine.read(&mut [0; 16]) == Took::End);
    }
}

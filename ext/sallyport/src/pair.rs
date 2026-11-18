//! What carry may ask of a connection's socket pair, and what it may take
//! for granted.
//!
//! Ruby holds one end of the pair and the stack holds the other. For each
//! way that bytes go, the kernel keeps the bytes that were written and not
//! yet read, and whether that way is shut down. It does not keep which end
//! shut it down: what Ruby writes is what we read, and one flag ends both.
//! Each method here says what carry relies on, and the tests below hold
//! Linux to it.

use crate::sock::Moved;
use crate::sys;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

// The module "pair" is this contract as the model "conn" has it. The
// lines of the module are here and beside the calls below.
//
// TLA-pair> \* This is a connection's socket pair as the kernel keeps it, with what
// TLA-pair> \* Ruby may do with its end. A state of the pair is a record with these
// TLA-pair> \* fields.
// TLA-pair> \*   fromRuby  the bytes that Ruby wrote and the stack has not read
// TLA-pair> \*   forRuby   the bytes that the stack wrote and Ruby has not read
// TLA-pair> \*   fromShut  no more goes from Ruby to the stack, because Ruby has shut
// TLA-pair> \*             down its writing or the stack its reading
// TLA-pair> \*   forShut   no more goes from the stack to Ruby
// TLA-pair> \*   gone      Ruby's end is not closed ("no"), is being closed ("going")
// TLA-pair> \*             or is closed ("yes")
// TLA-pair> \*   err       Ruby closed its end with bytes unread, and the stack has yet
// TLA-pair> \*             to be told
// TLA-pair> \*   quota     the bytes that Ruby may still write
// TLA-pair> EXTENDS Naturals
// TLA-pair> CONSTANTS PairCap, Budget
// TLA-pair> When(cond, x) == IF cond THEN {x} ELSE {}
// TLA-pair> New == [fromRuby |-> 0, forRuby |-> 0, fromShut |-> FALSE, forShut |-> FALSE,
// TLA-pair>         gone |-> "no", err |-> FALSE, quota |-> Budget]
// TLA-pair> \* Ruby may write, read, shut down either way and close, in any order and
// TLA-pair> \* at any time. Each of these is the set of the states that a move of
// TLA-pair> \* Ruby leads to, and it is empty when Ruby cannot make the move.
// TLA-pair> Writes(p) == When(p.gone = "no" /\ ~p.fromShut /\ p.fromRuby < PairCap /\ p.quota > 0,
// TLA-pair>                   [p EXCEPT !.fromRuby = @ + 1, !.quota = @ - 1])
// TLA-pair> Reads(p) == When(p.gone = "no" /\ p.forRuby > 0, [p EXCEPT !.forRuby = @ - 1])
// TLA-pair> Shuts(p) == When(p.gone = "no" /\ ~p.fromShut, [p EXCEPT !.fromShut = TRUE])
// TLA-pair>        \cup When(p.gone = "no" /\ ~p.forShut, [p EXCEPT !.forShut = TRUE])
// TLA-pair> \* Linux closes an end in two steps. It first shuts that end down, and a
// TLA-pair> \* write to the other end fails from then on. It then tells the other end:
// TLA-pair> \* poll reports the hangup, and the error if bytes were left unread.
// TLA-pair> Closes(p) == When(p.gone = "no", [p EXCEPT !.gone = "going"])
// TLA-pair>         \cup When(p.gone = "going", [p EXCEPT !.gone = "yes", !.fromShut = TRUE, !.forShut = TRUE,
// TLA-pair>                                               !.err = p.forRuby > 0, !.forRuby = 0])
// TLA-pair> Ruby(p) == Writes(p) \cup Reads(p) \cup Shuts(p) \cup Closes(p)

/// What a read of our end found.
#[derive(Debug, PartialEq)]
pub enum Took {
    /// This many bytes that Ruby wrote.
    Bytes(usize),
    /// Nothing yet, and Ruby may still write.
    Nothing,
    /// The end: no more comes from the pair.
    End,
    /// Ruby closed its end, and it had not read all that it was given.
    Reset,
}

/// What a write to our end found.
#[derive(Debug, PartialEq)]
pub enum Gave {
    /// The pair took this many bytes.
    Bytes(usize),
    /// The pair has no room until Ruby reads.
    Full,
    /// The pair takes no more, because Ruby will read no more.
    Refused,
}

impl Moved for Took {
    fn bytes(&self) -> usize {
        if let Took::Bytes(n) = self {
            *n
        } else {
            0
        }
    }
}

impl Moved for Gave {
    fn bytes(&self) -> usize {
        if let Gave::Bytes(n) = self {
            *n
        } else {
            0
        }
    }
}

/// poll reports one of these of our end, whatever events it is asked
/// about.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Hangup {
    /// Bytes can still go one way or the other.
    No,
    /// No more can go either way.
    Yes,
    /// Ruby closed its end, and it had not read all that it was given.
    Unread,
}

/// Our end of the pair, and what it has said so far.
pub struct Pair {
    fd: OwnedFd,
    done: bool,
    deaf: bool,
    told: bool,
}

impl Pair {
    pub fn new(fd: OwnedFd) -> Pair {
        Pair { fd, done: false, deaf: false, told: false }
    }

    // TLA-pair> \* Pair::read says one of these, and takes bytes if there are some. It
    // TLA-pair> \* tells once of bytes that Ruby left unread.
    // TLA-pair> Read(p) == IF p.fromRuby > 0 THEN "bytes" ELSE IF p.err THEN "reset"
    // TLA-pair>            ELSE IF p.fromShut THEN "end" ELSE "nothing"
    // TLA-pair> Took(p, n) == [p EXCEPT !.fromRuby = @ - n]
    // TLA-pair> Heard(p) == [p EXCEPT !.err = FALSE]
    /// Reads bytes that Ruby wrote, the oldest first. A read that finds
    /// none says why. It tells once of bytes that Ruby left unread when it
    /// closed its end. After that it gives the end, if Ruby has closed its
    /// end or shut down its writing, or if we have shut down our reading
    /// (`a_read_gives_the_bytes_and_then_says_why_there_are_no_more`).
    pub fn read(&mut self, buf: &mut [u8]) -> Took {
        match sys::read(self.fd.as_raw_fd(), buf) {
            n if n > 0 => Took::Bytes(n as usize),
            0 => {
                self.done = true;
                Took::End
            }
            sys::AGAIN => Took::Nothing,
            _ => Took::Reset,
        }
    }

    /// Says whether no more comes from the pair: a read has given the
    /// end, or `stop` has shut down our reading.
    pub fn done(&self) -> bool {
        self.done
    }

    // TLA-pair> \* Pair::stop
    // TLA-pair> Stop(p) == [p EXCEPT !.fromShut = TRUE]
    /// Ends what Ruby may write: a write by Ruby fails from now on. Ruby
    /// can still read what it is given
    /// (`a_pair_whose_reading_we_stop_refuses_what_ruby_writes`).
    pub fn stop(&mut self) {
        sys::shutdown(self.fd.as_raw_fd(), libc::SHUT_RD);
        self.done = true;
    }

    // TLA-pair> \* Pair::write says one of these, and gives bytes if the pair takes them.
    // TLA-pair> Write(p) == IF p.forShut \/ p.gone # "no" THEN "refused"
    // TLA-pair>             ELSE IF p.forRuby < PairCap THEN "bytes" ELSE "full"
    // TLA-pair> Gave(p, n) == [p EXCEPT !.forRuby = @ + n]
    /// Writes bytes for Ruby. The pair refuses them once Ruby has closed
    /// its end or shut down its reading, and from then on
    /// (`a_write_is_refused_once_ruby_reads_no_more`). While Ruby closes
    /// its end, the pair refuses them a moment before poll reports the
    /// hangup: Linux shuts down the end that closes before it tells the
    /// other. No test can hold that moment.
    pub fn write(&mut self, buf: &[u8]) -> Gave {
        match sys::send(self.fd.as_raw_fd(), buf) {
            n if n > 0 => Gave::Bytes(n as usize),
            0 | sys::AGAIN => Gave::Full,
            _ => {
                self.deaf = true;
                Gave::Refused
            }
        }
    }

    /// Says whether the pair has refused a write.
    pub fn deaf(&self) -> bool {
        self.deaf
    }

    // TLA-pair> \* Pair::end
    // TLA-pair> End(p) == [p EXCEPT !.forShut = TRUE]
    /// Ends what Ruby reads, after the bytes that were written already
    /// (`ruby_reads_the_end_after_what_it_was_given`).
    pub fn end(&mut self) {
        sys::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR);
        self.told = true;
    }

    /// Says whether `end` has ended what Ruby reads.
    pub fn told(&self) -> bool {
        self.told
    }

    // TLA-pair> \* Pair::shut
    // TLA-pair> Shut(p) == [p EXCEPT !.fromShut = TRUE, !.forShut = TRUE]
    /// Shuts our end down both ways. To our end, the pair is then what a
    /// pair is whose other end Ruby has closed: a read gives what Ruby had
    /// written and then the end, a write is refused, and poll reports a
    /// hangup. Ruby reads what it was given and then the end, and a write
    /// by Ruby fails (`a_pair_that_we_shut_down_is_as_one_that_ruby_closed`).
    pub fn shut(&self) {
        sys::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR);
    }

    // TLA-pair> \* Pair::hangup. poll reports a hangup when no more can go either way,
    // TLA-pair> \* and it tells of bytes that Ruby left unread until a read has.
    // TLA-pair> HungUp(p) == p.fromShut /\ p.forShut
    // TLA-pair> Unread(p) == p.err
    /// Says what poll reports of our end. It reports a hangup when no
    /// more can go either way: Ruby has closed its end, or each way is
    /// shut down, by either end. It reports no hangup for a Ruby that has
    /// only shut down its reading or only its writing
    /// (`poll_reports_a_hangup_when_no_more_can_go_either_way`). It tells
    /// of bytes that Ruby left unread when it closed, until a read has
    /// told of them (`a_read_gives_the_bytes_and_then_says_why_there_are_no_more`).
    pub fn hangup(&self) -> Hangup {
        match sys::revents(self.fd.as_raw_fd(), 0) {
            r if r & libc::POLLERR != 0 => Hangup::Unread,
            r if r & libc::POLLHUP != 0 => Hangup::Yes,
            _ => Hangup::No,
        }
    }

    /// Sends the status that is the first byte of a connection that Ruby
    /// makes.
    pub fn say(&self, status: u8) {
        sys::send(self.fd.as_raw_fd(), &[status]);
    }

    // TLA-pair> \* poll reports that there is something to read when a read would not say
    // TLA-pair> \* "nothing". It reports room for a write later than a write would find
    // TLA-pair> \* it, and it does not report a pair that would refuse a write.
    // TLA-pair> Readable(p) == p.fromRuby > 0 \/ p.fromShut
    // TLA-pair> Writable(p) == 4 * p.forRuby <= PairCap
    /// Returns our end as poll takes it. poll reports that there is
    /// something to read when a read would give bytes or the end. It
    /// reports room for a write later than a write would find it: only
    /// when Ruby has no more than about a quarter of the pair left to
    /// read. And it does not report that the pair would refuse a write
    /// (`poll_reports_room_later_than_a_write_finds_it`).
    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Returns how many bytes that Ruby wrote wait to be read.
    pub fn waiting(&self) -> usize {
        sys::readable(self.fd.as_raw_fd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    /// Makes a pair, and returns our end and Ruby's end.
    fn pair() -> (Pair, UnixStream) {
        let (ours, theirs) = sys::socketpair(libc::SOCK_STREAM).unwrap();
        let ruby = UnixStream::from(theirs);
        ruby.set_nonblocking(true).unwrap();
        (Pair::new(ours), ruby)
    }

    /// Says whether poll reports that our end has room for a write.
    fn room(ours: &Pair) -> bool {
        sys::revents(ours.raw(), libc::POLLOUT) & libc::POLLOUT != 0
    }

    /// Says whether poll reports that our end has something to read.
    fn readable(ours: &Pair) -> bool {
        sys::revents(ours.raw(), libc::POLLIN) & libc::POLLIN != 0
    }

    /// Writes to our end until the pair is full, and returns how many
    /// bytes it took.
    fn fill(ours: &mut Pair) -> usize {
        let mut took = 0;
        while let Gave::Bytes(n) = ours.write(&[7; 1024]) {
            took += n;
        }
        took
    }

    #[test]
    fn a_read_gives_the_bytes_and_then_says_why_there_are_no_more() {
        let buf = &mut [0; 16];
        let (mut ours, mut ruby) = pair();
        assert!(ours.read(buf) == Took::Nothing && !readable(&ours));
        ruby.write_all(b"abc").unwrap();
        assert!(readable(&ours) && ours.read(buf) == Took::Bytes(3) && ours.read(buf) == Took::Nothing);
        ruby.write_all(b"de").unwrap();
        ruby.shutdown(Shutdown::Write).unwrap();
        assert!(ours.read(buf) == Took::Bytes(2) && !ours.done());
        assert!(readable(&ours) && ours.read(buf) == Took::End && ours.done());

        // Ruby closes with bytes unread, after it wrote some.
        let (mut ours, mut ruby) = pair();
        ruby.write_all(b"abc").unwrap();
        assert_eq!(ours.write(b"xyz"), Gave::Bytes(3));
        drop(ruby);
        assert_eq!(ours.hangup(), Hangup::Unread);
        assert!(ours.read(buf) == Took::Bytes(3) && ours.hangup() == Hangup::Unread);
        assert!(ours.read(buf) == Took::Reset && ours.hangup() == Hangup::Yes && !ours.done());
        assert!(ours.read(buf) == Took::End && ours.done());

        // Ruby closes with nothing unread.
        let (mut ours, mut ruby) = pair();
        ruby.write_all(b"abc").unwrap();
        drop(ruby);
        assert!(ours.hangup() == Hangup::Yes && ours.read(buf) == Took::Bytes(3) && ours.read(buf) == Took::End);
    }

    #[test]
    fn a_write_is_refused_once_ruby_reads_no_more() {
        let (mut ours, ruby) = pair();
        assert!(ours.write(b"abc") == Gave::Bytes(3) && !ours.deaf());
        ruby.shutdown(Shutdown::Read).unwrap();
        assert!(ours.write(b"abc") == Gave::Refused && ours.deaf());
        assert_eq!(ours.hangup(), Hangup::No, "Ruby may still write");

        let (mut ours, ruby) = pair();
        drop(ruby);
        assert!(ours.write(b"abc") == Gave::Refused && ours.hangup() == Hangup::Yes);
    }

    #[test]
    fn poll_reports_room_later_than_a_write_finds_it() {
        let (mut ours, mut ruby) = pair();
        assert!(room(&ours));
        let all = fill(&mut ours);
        assert!(all > 4096 && !room(&ours));
        let mut read = ruby.read(&mut [0; 2048]).unwrap();
        assert!(matches!(ours.write(&[7]), Gave::Bytes(1)) && !room(&ours));
        // poll reports room when about a quarter is left to read.
        let buf = &mut [0; 1024];
        while !room(&ours) {
            read += ruby.read(buf).unwrap();
        }
        assert!(read > all / 2 && read < all, "{read} of {all}");

        // It does not report a pair that would refuse the write.
        let (mut ours, ruby) = pair();
        fill(&mut ours);
        ruby.shutdown(Shutdown::Read).unwrap();
        assert!(!room(&ours) && ours.write(&[7]) == Gave::Refused && !room(&ours));
    }

    #[test]
    fn poll_reports_a_hangup_when_no_more_can_go_either_way() {
        // Each end shuts down its writing.
        let (mut ours, ruby) = pair();
        ruby.shutdown(Shutdown::Write).unwrap();
        assert_eq!(ours.hangup(), Hangup::No);
        ours.end();
        assert!(ours.hangup() == Hangup::Yes && ours.told());

        // Ruby shuts its end down both ways, and does not close it.
        let (ours, ruby) = pair();
        ruby.shutdown(Shutdown::Read).unwrap();
        assert_eq!(ours.hangup(), Hangup::No);
        ruby.shutdown(Shutdown::Write).unwrap();
        assert_eq!(ours.hangup(), Hangup::Yes);

        // We stop what Ruby writes, and Ruby stops reading.
        let (mut ours, ruby) = pair();
        ours.stop();
        assert_eq!(ours.hangup(), Hangup::No);
        ruby.shutdown(Shutdown::Read).unwrap();
        assert_eq!(ours.hangup(), Hangup::Yes);
    }

    #[test]
    fn a_pair_whose_reading_we_stop_refuses_what_ruby_writes() {
        let (mut ours, mut ruby) = pair();
        ruby.write_all(b"before").unwrap();
        ours.stop();
        assert!(ours.done());
        assert_eq!(ruby.write(b"after").unwrap_err().kind(), ErrorKind::BrokenPipe);
        assert_eq!(ours.write(b"abc"), Gave::Bytes(3));
        let buf = &mut [0; 16];
        assert_eq!(ruby.read(buf).unwrap(), 3);
        assert_eq!(ruby.read(buf).unwrap_err().kind(), ErrorKind::WouldBlock, "what Ruby reads has not ended");
    }

    #[test]
    fn ruby_reads_the_end_after_what_it_was_given() {
        let (mut ours, mut ruby) = pair();
        assert_eq!(ours.write(b"abc"), Gave::Bytes(3));
        ours.end();
        assert_eq!(ours.write(b"abc"), Gave::Refused);
        let buf = &mut [0; 16];
        assert!(ruby.read(buf).unwrap() == 3 && ruby.read(buf).unwrap() == 0);
        ruby.write_all(b"still").unwrap();
        assert_eq!(ours.read(buf), Took::Bytes(5));
    }

    #[test]
    fn a_pair_that_we_shut_down_is_as_one_that_ruby_closed() {
        let (mut ours, mut ruby) = pair();
        ruby.write_all(b"before").unwrap();
        assert_eq!(ours.write(b"abc"), Gave::Bytes(3));
        ours.shut();
        assert_eq!(ours.hangup(), Hangup::Yes);
        assert_eq!(ruby.write(b"after").unwrap_err().kind(), ErrorKind::BrokenPipe);
        let buf = &mut [0; 16];
        assert!(ours.read(buf) == Took::Bytes(6) && ours.read(buf) == Took::End);
        assert_eq!(ours.write(b"abc"), Gave::Refused);
        assert!(ruby.read(buf).unwrap() == 3 && ruby.read(buf).unwrap() == 0);
    }
}

//! The library reaches the operating system through this module, which
//! keeps the unsafe calls in one place.

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// What a read returns when it would have to wait.
pub const AGAIN: isize = -2;
/// What a write returns when the other end takes no more.
pub const PIPE: isize = -3;

/// Maps what a system call returned to a count, AGAIN, PIPE, or -1 for
/// any other error.
fn result(n: isize) -> isize {
    if n >= 0 {
        return n;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR) => AGAIN,
        Some(libc::EPIPE) => PIPE,
        _ => -1,
    }
}

pub fn read(fd: RawFd, buf: &mut [u8]) -> isize {
    result(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) })
}

/// Sends on a socket without waiting. If the other end is closed, the
/// error is returned and no signal is raised.
pub fn send(fd: RawFd, buf: &[u8]) -> isize {
    result(unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) })
}

/// Returns how many bytes wait to be read from a descriptor, or 0 if
/// that cannot be told.
pub fn readable(fd: RawFd) -> usize {
    let mut n: libc::c_int = 0;
    unsafe { libc::ioctl(fd, libc::FIONREAD, &raw mut n) };
    n.max(0) as usize
}

/// Ends what the other end of a socket pair can read, after what was
/// sent already.
pub fn shutdown_write(fd: RawFd) {
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
}

/// Ends what the other end of a socket pair can write: a write to it
/// fails from now on. What it wrote already can still be read here.
pub fn shutdown_read(fd: RawFd) {
    unsafe { libc::shutdown(fd, libc::SHUT_RD) };
}

/// Shuts an end of a socket pair down both ways. The other end reads what
/// was sent already and then the end, and a write to it fails.
pub fn shutdown(fd: RawFd) {
    unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
}

/// poll(2) reports one of these of an end of a socket pair, whatever
/// events it is asked about.
#[derive(Clone, Copy, PartialEq)]
pub enum Hangup {
    /// Bytes can still go one way or the other.
    No,
    /// No more can go either way: the other end is closed, or this end is
    /// shut down both ways, or each end has shut down its writing.
    Yes,
    /// The other end is closed, and it had not read all that it was sent.
    Unread,
}

pub fn hangup(fd: RawFd) -> Hangup {
    let mut p = libc::pollfd { fd, events: 0, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    match p.revents {
        r if r & libc::POLLERR != 0 => Hangup::Unread,
        r if r & libc::POLLHUP != 0 => Hangup::Yes,
        _ => Hangup::No,
    }
}

/// Says whether the other end of a socket pair will send no more: it is
/// closed, or it has shut down its writing.
pub fn ended(fd: RawFd) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLRDHUP, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0
}

/// Waits until a descriptor is ready or the time has passed, for a second
/// at most.
pub fn poll(fds: &mut [libc::pollfd], wait: Duration) {
    // A wait of less than a millisecond is rounded up, since poll would
    // otherwise return at once and the caller would spin.
    let ms = wait.as_micros().div_ceil(1000).min(1000) as libc::c_int;
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
}

/// Makes a pipe whose ends do not block, and returns its read end and its
/// write end.
pub fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut ends = [0 as RawFd; 2];
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) })
}

/// Writes a byte to a pipe. A full pipe takes no more, which is as good:
/// its reader has a byte to wake for.
pub fn write_byte(fd: RawFd) {
    unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
}

/// Empties a pipe.
pub fn drain(fd: RawFd) {
    let mut buf = [0u8; 64];
    while read(fd, &mut buf) > 0 {}
}

/// Makes a Unix socket pair of a kind: SOCK_STREAM for a connection, or
/// SOCK_SEQPACKET for a listener, whose messages must stay apart. Returns
/// our end, which does not block, and Ruby's end.
pub fn socketpair(kind: libc::c_int) -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut ends = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, kind | libc::SOCK_CLOEXEC, 0, ends.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::fcntl(ends[0], libc::F_SETFL, libc::O_NONBLOCK) };
    Ok(unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) })
}

/// What became of a message that send_fd was given.
pub enum Sent {
    Ok,
    /// The socket's buffer has no room for it.
    Full,
    /// The other end is closed.
    Gone,
}

/// Sends a message on a socket without waiting, and a descriptor with it
/// (SCM_RIGHTS).
pub fn send_fd(socket: RawFd, message: &[u8], fd: RawFd) -> Sent {
    // The buffer is of u64 so that it is aligned for a cmsghdr, and it is
    // longer than CMSG_SPACE(4).
    let mut control = [0u64; 4];
    let mut iov = libc::iovec { iov_base: message.as_ptr() as *mut libc::c_void, iov_len: message.len() };
    let sent = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let header = libc::CMSG_FIRSTHDR(&raw const msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as _;
        libc::CMSG_DATA(header).cast::<RawFd>().write_unaligned(fd);
        libc::sendmsg(socket, &raw const msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
    };
    match result(sent) {
        AGAIN => Sent::Full,
        n if n >= 0 => Sent::Ok,
        _ => Sent::Gone,
    }
}

/// Makes a UDP socket that does not block, bound to the port, or to any
/// port if the port is 0. It is an IPv6 socket that takes IPv4 as well
/// where the system has IPv6, and an IPv4 socket elsewhere. Returns the
/// socket and whether it is an IPv6 one.
pub fn udp_socket(port: u16) -> std::io::Result<(UdpSocket, bool)> {
    let (socket, v6) = match unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) } {
        fd if fd >= 0 => {
            let socket = unsafe { UdpSocket::from_raw_fd(fd) };
            let (off, addr) = (
                0 as libc::c_int,
                libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: port.to_be(),
                    ..unsafe { std::mem::zeroed() }
                },
            );
            let size = |of: usize| of as libc::socklen_t;
            let bound = unsafe {
                libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, (&raw const off).cast(), size(4));
                libc::bind(fd, (&raw const addr).cast(), size(std::mem::size_of_val(&addr)))
            };
            if bound != 0 {
                return Err(std::io::Error::last_os_error());
            }
            (socket, true)
        }
        _ => (UdpSocket::bind(("0.0.0.0", port))?, false),
    };
    socket.set_nonblocking(true)?;
    // The socket drops a burst that its buffer cannot hold, so a large
    // buffer is asked for. The system gives what its limits allow.
    let want: libc::c_int = 4 << 20;
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, option, (&raw const want).cast(), 4) };
    }
    Ok((socket, v6))
}

/// Sends a datagram. If the socket's buffer is full the datagram is
/// dropped, as a full link would drop it.
pub fn udp_send(socket: &UdpSocket, v6: bool, datagram: &[u8], to: SocketAddr) {
    let to = match (v6, to) {
        (true, SocketAddr::V4(a)) => SocketAddr::new(a.ip().to_ipv6_mapped().into(), a.port()),
        _ => to,
    };
    let _ = socket.send_to(datagram, to);
}

/// Returns bytes from the system's random number generator.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    random_fill(&mut bytes);
    bytes
}

/// Fills the buffer, of 256 bytes at most, from the system's random
/// number generator. getrandom(2) needs no descriptor, so it does not
/// fail when the process has none to spare.
pub fn random_fill(buf: &mut [u8]) {
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert_eq!(n, buf.len() as isize, "getrandom: {}", std::io::Error::last_os_error());
}

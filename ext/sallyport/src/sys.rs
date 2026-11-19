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
/// any other error. A call that the system had no memory for is one to
/// make again, as one that would have had to wait is: the system has the
/// memory a moment later, and the descriptor is as it was.
fn result(n: isize) -> isize {
    if n >= 0 {
        return n;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN | libc::EINTR | libc::ENOBUFS | libc::ENOMEM) => AGAIN,
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

/// Shuts down an end of a socket pair. `how` is SHUT_RD for its reading,
/// SHUT_WR for its writing, or SHUT_RDWR for both.
pub fn shutdown(fd: RawFd, how: libc::c_int) {
    unsafe { libc::shutdown(fd, how) };
}

/// Returns what poll(2) reports of a descriptor now, when it is asked
/// about these events. It reports a hangup and an error whatever it is
/// asked.
pub fn revents(fd: RawFd, events: libc::c_short) -> libc::c_short {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents
}

/// Says whether the other end of a socket pair will send no more: it is
/// closed, or it has shut down its writing.
pub fn ended(fd: RawFd) -> bool {
    revents(fd, libc::POLLRDHUP) & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0
}

/// Waits until a descriptor is ready or the time has passed, for a second
/// at most.
pub fn poll(fds: &mut [libc::pollfd], wait: Duration) {
    // A wait of less than a millisecond is rounded up, since poll would
    // otherwise return at once and the caller would spin.
    let ms = wait.as_micros().div_ceil(1000).min(1000) as libc::c_int;
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
}

/// Runs `f` with every signal blocked, and returns what it gives. A
/// thread that is made meanwhile has every signal blocked for its life,
/// so the system delivers a signal of the process to another thread.
pub fn with_signals_blocked<T>(f: impl FnOnce() -> T) -> T {
    unsafe {
        let (mut all, mut before): (libc::sigset_t, libc::sigset_t) = (std::mem::zeroed(), std::mem::zeroed());
        libc::sigfillset(&raw mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const all, &raw mut before);
        let given = f();
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const before, std::ptr::null_mut());
        given
    }
}

/// Makes an eventfd that does not block. It is a count that poll can
/// wait on: poll reports it as readable while the count is not 0. It is
/// one descriptor, so it has no end that a writer can find closed.
pub fn eventfd() -> std::io::Result<OwnedFd> {
    match unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) } {
        fd if fd >= 0 => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Adds one to the count of an eventfd, which does not wait.
pub fn signal(fd: RawFd) {
    unsafe { libc::write(fd, 1u64.to_ne_bytes().as_ptr().cast(), 8) };
}

/// Sets the count of an eventfd to 0.
pub fn drain(fd: RawFd) {
    read(fd, &mut [0; 8]);
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

/// Sends a message on a socket without waiting, and a descriptor with it
/// (SCM_RIGHTS). Returns what `send` returns.
pub fn send_fd(socket: RawFd, message: &[u8], fd: RawFd) -> isize {
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
    result(sent)
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
        // Only a system that has no IPv6 gets an IPv4 socket. The call
        // can fail for another cause, such as the want of a descriptor.
        // That is a failure, and a tunnel is not left without IPv6 for
        // it.
        _ if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAFNOSUPPORT) => {
            (UdpSocket::bind(("0.0.0.0", port))?, false)
        }
        _ => return Err(std::io::Error::last_os_error()),
    };
    socket.set_nonblocking(true)?;
    // The socket drops a burst that its buffer cannot hold, so a large
    // buffer is asked for. The system gives what its limits allow.
    let want: libc::c_int = 4 << 20;
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, option, (&raw const want).cast(), 4) };
    }
    // An IPv4 datagram leaves without the mark that forbids a router to
    // cut it up, as a datagram of the kernel's WireGuard does. With the
    // mark, a link on the way drops a datagram that is too large for it.
    // The system learns of that only from an ICMP message, and many a
    // path lets none through.
    let whole: libc::c_int = libc::IP_PMTUDISC_DONT;
    unsafe {
        libc::setsockopt(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, (&raw const whole).cast(), 4)
    };
    Ok((socket, v6))
}

/// Returns the address of a datagram's sender as a peer's endpoint keeps
/// it. An IPv6 socket gives an IPv4 sender an IPv6 address, and udp_send
/// takes the IPv4 one. Another IPv6 address is kept whole. Its scope
/// says which link a link-local sender is on, and an answer needs it.
pub fn udp_from(from: SocketAddr) -> SocketAddr {
    match from {
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().map_or(from, |v4| SocketAddr::new(v4.into(), v6.port())),
        SocketAddr::V4(_) => from,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn a_call_that_found_no_memory_is_one_to_make_again() {
        let failed = |errno: libc::c_int| {
            unsafe { *libc::__errno_location() = errno };
            result(-1)
        };
        assert_eq!([libc::EAGAIN, libc::EINTR, libc::ENOBUFS, libc::ENOMEM].map(failed), [AGAIN; 4]);
        assert_eq!([libc::EPIPE, libc::ECONNRESET, libc::EBADF].map(failed), [PIPE, -1, -1]);
    }

    #[test]
    fn a_datagram_may_be_cut_up_on_its_way() {
        let (socket, _) = udp_socket(0).unwrap();
        let (mut mode, mut size): (libc::c_int, libc::socklen_t) = (-1, 4);
        let got = unsafe {
            let (mode, size) = ((&raw mut mode).cast(), &raw mut size);
            libc::getsockopt(socket.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, mode, size)
        };
        assert_eq!((got, mode), (0, libc::IP_PMTUDISC_DONT));
    }

    #[test]
    fn a_sender_keeps_its_scope_and_an_ipv4_sender_its_family() {
        let mapped = SocketAddr::new("::ffff:192.0.2.1".parse().unwrap(), 7);
        assert_eq!(udp_from(mapped), "192.0.2.1:7".parse().unwrap());
        let local = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse::<Ipv6Addr>().unwrap(), 7, 0, 3));
        assert_eq!(udp_from(local), local);
        let plain: SocketAddr = "192.0.2.1:7".parse().unwrap();
        assert_eq!(udp_from(plain), plain);
    }
}

//! A tunnel's thread owns the UDP socket and the WireGuard sessions, and
//! serves them from one loop that never takes Ruby's GVL.

use crate::config::Config;
use crate::peers::Peers;
use crate::sys;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// boringtun's timers run this often.
const TICK: Duration = Duration::from_millis(250);
/// One turn of the loop takes this many datagrams from the UDP socket at
/// most. It is many because a datagram that waits in the kernel's buffer
/// is dropped when the buffer fills, and one that has been taken is not.
const UDP_BATCH: usize = 1024;

/// A tunnel's thread shares this with its handle.
pub struct Shared {
    /// The pipe that wakes the loop. It is closed with the handle, which
    /// is the last to hold it, once the thread has ended.
    pub wake_r: OwnedFd,
    pub wake_w: OwnedFd,
    pub stop: AtomicBool,
    /// The state of the peers as Peers::stats writes it, and as it was
    /// when the timers last ran.
    pub stats: Mutex<String>,
}

impl Shared {
    pub fn wake(&self) {
        sys::write_byte(self.wake_w.as_raw_fd());
    }
}

pub struct Engine {
    shared: Arc<Shared>,
    udp: UdpSocket,
    /// The UDP socket is an IPv6 one, which takes an IPv4 address in its
    /// mapped form.
    udp_v6: bool,
    peers: Peers,
    next_tick: Instant,
    buf: Vec<u8>,
}

impl Engine {
    /// Makes the engine of a tunnel around its UDP socket, as
    /// sys::udp_socket returns it, and the two ends of the pipe that wakes
    /// it. An error is a fault in the configuration.
    pub fn new(
        cfg: &Config,
        (udp, udp_v6): (UdpSocket, bool),
        (wake_r, wake_w): (OwnedFd, OwnedFd),
    ) -> Result<(Engine, Arc<Shared>), String> {
        let peers = Peers::new(cfg)?;
        let shared = Arc::new(Shared { wake_r, wake_w, stop: AtomicBool::new(false), stats: Mutex::default() });
        let engine =
            Engine { shared: shared.clone(), udp, udp_v6, peers, next_tick: Instant::now(), buf: vec![0; 65536] };
        engine.publish();
        Ok((engine, shared))
    }

    /// Writes the state of the peers where sp_stats reads it.
    fn publish(&self) {
        let mut text = String::new();
        self.peers.stats(&mut text);
        *self.shared.stats.lock().unwrap_or_else(|e| e.into_inner()) = text;
    }

    /// Takes datagrams from the UDP socket and gives them to the peers.
    /// Returns whether it stopped with more left to take.
    fn udp_in(&mut self) -> bool {
        for _ in 0..UDP_BATCH {
            let Ok((len, from)) = self.udp.recv_from(&mut self.buf) else { return false };
            let from = SocketAddr::new(from.ip().to_canonical(), from.port());
            let (udp, v6) = (&self.udp, self.udp_v6);
            // There is nothing yet to give an IP packet to.
            self.peers.receive(&self.buf[..len], from, &mut |d, to| sys::udp_send(udp, v6, d, to));
        }
        true
    }

    fn tick(&mut self) {
        let (udp, v6) = (&self.udp, self.udp_v6);
        self.peers.tick(&mut |d, to| sys::udp_send(udp, v6, d, to));
        self.publish();
    }

    pub fn run(mut self) {
        while !self.shared.stop.load(Ordering::Acquire) {
            let more = self.udp_in();
            if Instant::now() >= self.next_tick {
                self.tick();
                self.next_tick = Instant::now() + TICK;
            }
            let wait = if more { Duration::ZERO } else { self.next_tick.saturating_duration_since(Instant::now()) };
            let mut fds = [self.shared.wake_r.as_raw_fd(), self.udp.as_raw_fd()].map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
            sys::poll(&mut fds, wait);
            if fds[0].revents != 0 {
                sys::drain(self.shared.wake_r.as_raw_fd());
            }
        }
    }
}

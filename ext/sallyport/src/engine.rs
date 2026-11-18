//! A tunnel's thread owns the UDP socket, the WireGuard sessions and the
//! TCP stack, and serves them from one loop that never takes Ruby's GVL.

use crate::config::Config;
use crate::packet::describe;
use crate::peers::{Dropped, Peers};
use crate::sys;
use crate::tcp::{status, Stack};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// boringtun's timers run this often.
const TICK: Duration = Duration::from_millis(250);
/// One turn of the loop takes this many datagrams from the UDP socket at
/// most. It is many because a datagram that waits in the kernel's buffer
/// is dropped when the buffer fills, and one that has been taken is not.
const UDP_BATCH: usize = 1024;

/// A command is what a call into the library asks of a tunnel's thread.
/// It carries our end of a socket pair, which is closed if the command is
/// dropped.
pub enum Cmd {
    Connect { fd: OwnedFd, addr: IpAddr, port: u16 },
    Listen { fd: OwnedFd, port: u16, backlog: usize },
}

/// A caller asks the thread to describe the tunnel, and the thread
/// answers at the next turn of its loop.
#[derive(Default)]
pub enum Dump {
    #[default]
    None,
    Asked,
    Done(String),
}

/// A tunnel's thread shares this with its handle.
pub struct Shared {
    pub cmds: Mutex<Vec<Cmd>>,
    /// The thread has ended, and takes no more commands.
    pub dead: AtomicBool,
    /// The pipe that wakes the loop. It is closed with the handle, which
    /// is the last to hold it, once the thread has ended.
    pub wake_r: OwnedFd,
    pub wake_w: OwnedFd,
    pub stop: AtomicBool,
    /// How many milliseconds the thread may take to end its connections
    /// in order, once it is told to stop.
    pub linger: AtomicU32,
    /// The state of the peers as Peers::stats writes it, and as it was
    /// when the timers last ran.
    pub stats: Mutex<String>,
    /// How many connections the stack had when the loop last turned.
    pub connections: AtomicUsize,
    /// A caller waits on `dumped` while `dump` is asked for.
    pub dump: Mutex<Dump>,
    pub dumped: Condvar,
}

impl Shared {
    pub fn wake(&self) {
        sys::write_byte(self.wake_w.as_raw_fd());
    }
}

/// Knobs are settings for tests and for looking inside a tunnel. sp_open
/// takes them as text, with commas between them.
#[derive(Debug, Default, PartialEq)]
pub struct Knobs {
    /// `trace=N` keeps a line for each of the last N TCP packets, a
    /// million at most, and the tunnel's description then has them.
    pub trace: usize,
    /// `fail` has the thread panic when it is next asked to describe the
    /// tunnel. The tests use it to see what a failed tunnel does.
    pub fail: bool,
    /// `drop=PASS:MS` makes an outage. Once PASS datagrams have arrived,
    /// the thread drops those that arrive in the next MS milliseconds.
    pub drop: Option<(u64, Duration)>,
}

impl Knobs {
    pub fn parse(text: &str) -> Result<Knobs, String> {
        let mut knobs = Knobs::default();
        for knob in text.split(',').map(str::trim).filter(|knob| !knob.is_empty()) {
            let (name, value) = knob.split_once('=').unwrap_or((knob, ""));
            let bad = || format!("bad debug knob {knob:?}");
            match name {
                "trace" => knobs.trace = value.parse::<usize>().map_err(|_| bad())?.min(1_000_000),
                "fail" if value.is_empty() => knobs.fail = true,
                "drop" => {
                    let (pass, ms) = value.split_once(':').ok_or_else(bad)?;
                    let ms = Duration::from_millis(ms.parse().map_err(|_| bad())?);
                    knobs.drop = Some((pass.parse().map_err(|_| bad())?, ms));
                }
                _ => return Err(bad()),
            }
        }
        Ok(knobs)
    }
}

pub struct Engine {
    shared: Arc<Shared>,
    udp: UdpSocket,
    /// The UDP socket is an IPv6 one, which takes an IPv4 address in its
    /// mapped form.
    udp_v6: bool,
    peers: Peers,
    stack: Stack,
    next_tick: Instant,
    buf: Vec<u8>,
    /// These count the datagrams that have arrived, and the packets that
    /// the stack has sent.
    datagrams: u64,
    packets: u64,
    knobs: Knobs,
    /// The lines of the trace, and the moment that their times count
    /// from.
    trace: VecDeque<String>,
    epoch: Instant,
    /// When the outage that the `drop` knob makes is over.
    drop_until: Option<Instant>,
}

impl Engine {
    /// Makes the engine of a tunnel around its UDP socket, as
    /// sys::udp_socket returns it, and the two ends of the pipe that wakes
    /// it. An error is a fault in the configuration.
    pub fn new(
        cfg: &Config,
        knobs: Knobs,
        (udp, udp_v6): (UdpSocket, bool),
        (wake_r, wake_w): (OwnedFd, OwnedFd),
    ) -> Result<(Engine, Arc<Shared>), String> {
        let peers = Peers::new(cfg)?;
        let shared = Arc::new(Shared {
            cmds: Mutex::default(),
            dead: AtomicBool::new(false),
            wake_r,
            wake_w,
            stop: AtomicBool::new(false),
            linger: AtomicU32::new(0),
            stats: Mutex::default(),
            connections: AtomicUsize::new(0),
            dump: Mutex::default(),
            dumped: Condvar::new(),
        });
        let engine = Engine {
            shared: shared.clone(),
            udp,
            udp_v6,
            peers,
            stack: Stack::new(cfg),
            next_tick: Instant::now(),
            buf: vec![0; 65536],
            datagrams: 0,
            packets: 0,
            knobs,
            trace: VecDeque::new(),
            epoch: Instant::now(),
            drop_until: None,
        };
        engine.publish();
        Ok((engine, shared))
    }

    /// Writes the state of the peers where sp_stats reads it.
    fn publish(&self) {
        let mut text = String::new();
        self.peers.stats(&mut text);
        *self.shared.stats.lock().unwrap_or_else(|e| e.into_inner()) = text;
    }

    /// Takes the commands that have been queued, and does each.
    fn commands(&mut self) {
        let cmds = std::mem::take(&mut *self.shared.cmds.lock().unwrap_or_else(|e| e.into_inner()));
        for cmd in cmds {
            match cmd {
                Cmd::Connect { fd, addr, port } if self.peers.reaches(&addr) => self.stack.connect(fd, addr, port),
                Cmd::Connect { fd, .. } => Stack::refuse(fd, status::NO_ROUTE),
                Cmd::Listen { fd, port, backlog } => self.stack.listen(fd, port, backlog),
            }
        }
    }

    /// Takes datagrams from the UDP socket, and gives the stack the IP
    /// packets that they carry. Returns whether it stopped with more left
    /// to take.
    fn udp_in(&mut self) -> bool {
        for _ in 0..UDP_BATCH {
            let Ok((len, from)) = self.udp.recv_from(&mut self.buf) else { return false };
            self.datagrams += 1;
            if self.dropping() {
                continue;
            }
            let from = SocketAddr::new(from.ip().to_canonical(), from.port());
            let (udp, v6) = (&self.udp, self.udp_v6);
            let packet = self.peers.receive(&self.buf[..len], from, &mut |d, to| sys::udp_send(udp, v6, d, to));
            if let Some(packet) = packet {
                self.trace("in ", &packet);
                self.stack.receive(packet);
            }
        }
        true
    }

    /// Encrypts and sends the packets that the stack has queued.
    fn flush(&mut self) {
        while let Some(packet) = self.stack.transmit() {
            self.trace("out", &packet);
            self.packets += 1;
            let (udp, v6) = (&self.udp, self.udp_v6);
            self.peers.send(&packet, &mut |d, to| sys::udp_send(udp, v6, d, to));
        }
    }

    fn tick(&mut self) {
        let (udp, v6) = (&self.udp, self.udp_v6);
        self.peers.tick(&mut |d, to| sys::udp_send(udp, v6, d, to));
        self.publish();
    }

    pub fn run(mut self) {
        let (udp, v6) = (&self.udp, self.udp_v6);
        self.peers.start(&mut |d, to| sys::udp_send(udp, v6, d, to));
        let mut fds: Vec<libc::pollfd> = Vec::new();
        while !self.shared.stop.load(Ordering::Acquire) {
            self.commands();
            self.serve(&mut fds, TICK);
        }
        self.finish(&mut fds);
    }

    /// Makes one turn of the loop. It takes what has arrived, moves the
    /// connections, sends what they have to send, and then waits until
    /// there is more to do, or for `most` at the longest.
    fn serve(&mut self, fds: &mut Vec<libc::pollfd>, most: Duration) {
        let more = self.udp_in();
        if Instant::now() >= self.next_tick {
            self.tick();
            self.next_tick = Instant::now() + TICK;
        }
        let moved = self.stack.turn();
        self.flush();
        self.shared.connections.store(self.stack.connections(), Ordering::Relaxed);
        self.dump();

        let mut wait = self.next_tick.saturating_duration_since(Instant::now()).min(most);
        if let Some(delay) = self.stack.poll_delay() {
            wait = wait.min(delay);
        }
        // A connection that moved may have given its socket something to
        // send, which the next turn sends.
        if more || moved {
            wait = Duration::ZERO;
        }
        fds.clear();
        fds.extend([self.shared.wake_r.as_raw_fd(), self.udp.as_raw_fd()].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }));
        self.stack.poll_fds(fds);
        sys::poll(fds, wait);
        if fds[0].revents != 0 {
            sys::drain(self.shared.wake_r.as_raw_fd());
        }
    }

    /// Says whether the `drop` knob has the datagram that just arrived
    /// dropped.
    fn dropping(&mut self) -> bool {
        let Some((pass, span)) = self.knobs.drop else { return false };
        if self.datagrams <= pass {
            return false;
        }
        Instant::now() < *self.drop_until.get_or_insert_with(|| Instant::now() + span)
    }

    /// Keeps a line for a TCP packet that went `way`, if a trace is kept.
    /// The line shows the packet as it is inside the tunnel, where tcpdump
    /// cannot look.
    fn trace(&mut self, way: &str, packet: &[u8]) {
        if self.knobs.trace == 0 {
            return;
        }
        if let Some(line) = describe(packet) {
            if self.trace.len() == self.knobs.trace {
                self.trace.pop_front();
            }
            self.trace.push_back(format!("{:10.4} {way} {line}", self.epoch.elapsed().as_secs_f64()));
        }
    }

    /// Describes the tunnel for the caller that asked, if one did. The
    /// description is for a person who wants to know why something does
    /// not move.
    fn dump(&self) {
        let mut dump = self.shared.dump.lock().unwrap_or_else(|e| e.into_inner());
        if !matches!(*dump, Dump::Asked) {
            return;
        }
        assert!(!self.knobs.fail, "the tunnel's thread was told to fail");
        let Dropped { unknown, refused, disallowed } = self.peers.dropped;
        let mut text = format!(
            "{} datagrams in: {unknown} from no peer, {refused} refused, {disallowed} from a source not allowed\n\
             {} packets out\n\
             peers, each with its endpoint, the milliseconds since its handshake, and the bytes sent and received:\n",
            self.datagrams, self.packets
        );
        self.peers.stats(&mut text);
        self.stack.describe(&mut text);
        if self.knobs.trace > 0 {
            text += "the last TCP packets, each with the seconds since the tunnel started:\n";
            for line in &self.trace {
                text += line;
                text += "\n";
            }
        }
        *dump = Dump::Done(text);
        self.shared.dumped.notify_all();
    }

    /// Ends the connections in order, when Ruby has closed the tunnel.
    /// Each is treated as if Ruby had closed its end: what was written to
    /// it is sent, and then a FIN. The thread gives that as long as the
    /// linger allows. It then resets every connection that has not ended,
    /// so that no peer is left to wait for one that is gone.
    fn finish(&mut self, fds: &mut Vec<libc::pollfd>) {
        self.refuse_commands();
        self.stack.orphan();
        let until = Instant::now() + Duration::from_millis(self.shared.linger.load(Ordering::Acquire).into());
        while !self.stack.finished() && Instant::now() < until {
            self.serve(fds, Duration::from_millis(10).min(until.saturating_duration_since(Instant::now())));
        }
        self.stack.abort();
        self.stack.poll();
        self.flush();
    }

    /// Sees that no command is queued from now on, and drops those that
    /// are. A call queues a command under this lock, and only while `dead`
    /// is false, so none is left behind with its descriptor open.
    fn refuse_commands(&self) {
        let mut cmds = self.shared.cmds.lock().unwrap_or_else(|e| e.into_inner());
        self.shared.dead.store(true, Ordering::Release);
        cmds.clear();
    }
}

/// The thread ends when run returns, or with a panic. Either way the
/// engine is dropped, and every descriptor that the thread holds is
/// closed with it. Ruby's ends then reach end of file, so a tunnel that
/// has failed looks closed to Ruby, and not silent.
impl Drop for Engine {
    fn drop(&mut self) {
        self.refuse_commands();
        // A caller that waits for a description will get none.
        drop(self.shared.dump.lock());
        self.shared.dumped.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knobs_are_read_from_text() {
        assert_eq!(Knobs::parse("").unwrap(), Knobs::default());
        assert_eq!(Knobs::parse(" trace=40 ,").unwrap(), Knobs { trace: 40, ..Knobs::default() });
        let all = Knobs { trace: 1_000_000, fail: true, drop: Some((1500, Duration::from_millis(30))) };
        assert_eq!(Knobs::parse("fail,trace=5000000,drop=1500:30").unwrap(), all);
        for bad in ["trace", "trace=x", "trace=-1", "loud", "trace=1,loud", "fail=1", "drop=5", "drop=a:b"] {
            let knob = bad.rsplit(',').next().unwrap();
            assert_eq!(Knobs::parse(bad).unwrap_err(), format!("bad debug knob {knob:?}"));
        }
    }
}

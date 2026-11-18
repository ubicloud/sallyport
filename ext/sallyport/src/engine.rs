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

// The model "wake" is of what a tunnel's thread shares with the threads
// that call the library: how a call reaches the thread, and how the
// thread and its handle end. The lines of the model are beside the code
// that they describe, here and in lib.rs, and Ruby's part is in
// tunnel.rb. tools/tla gathers them, and `rake tla` checks them.
//
// TLA-wake@0> EXTENDS Naturals
// TLA-wake@0> CONSTANTS Callers,   \* the Ruby threads that each begin one connection
// TLA-wake@0>           PipeCap,   \* how many bytes the pipe holds
// TLA-wake@0>           MayPanic,  \* the tunnel's thread may panic at any point
// TLA-wake@0>           Ticks,     \* poll also returns for a timer
// TLA-wake@0>           Fault      \* the fault that a variant puts in, or "none"
// TLA-wake@0> \* The state is one record, so that a step says what it changes and no more.
// TLA-wake@0> VARIABLE s
// TLA-wake@0> Init == s = [cmds  |-> {},      \* Shared.cmds: the callers whose command is queued
// TLA-wake@0>              dead  |-> FALSE,   \* Shared.dead
// TLA-wake@0>              stop  |-> FALSE,   \* Shared.stop
// TLA-wake@0>              pipe  |-> 0,       \* how many bytes are in the pipe
// TLA-wake@0>              rOpen |-> TRUE,    \* the read end of the pipe is open
// TLA-wake@0>              wOpen |-> TRUE,    \* the write end of the pipe is open
// TLA-wake@0>              epc   |-> "top",   \* where the tunnel's thread is
// TLA-wake@0>              fd    |-> [c \in Callers |-> "none"],  \* who has the descriptor that each caller made
// TLA-wake@0>              cpc   |-> [c \in Callers |-> "idle"],  \* where each caller is
// TLA-wake@0>              kpc   |-> "idle",  \* where the thread that closes the tunnel is
// TLA-wake@0>              mon   |-> "none",  \* who holds the lock of the Ruby Tunnel
// TLA-wake@0>              held  |-> TRUE,    \* the Tunnel has the handle
// TLA-wake@0>              freed |-> FALSE]   \* the handle is freed
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

// TLA-wake@0> \* Shared::wake writes a byte into the pipe and does not wait. A pipe
// TLA-wake@0> \* that is full takes no more, and has no need to.
// TLA-wake@0> Woke(t) == [t EXCEPT !.pipe = IF @ < PipeCap THEN @ + 1 ELSE @]
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
    /// `sack` leaves the offer of selective acknowledgement in the SYNs,
    /// which the stack otherwise takes out.
    pub sack: bool,
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
                "sack" if value.is_empty() => knobs.sack = true,
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
            stack: Stack::new(cfg, knobs.sack),
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

    // TLA-wake> \* The thread takes every queued command at once, under the lock.
    // TLA-wake> ETake == /\ s.epc = "take"
    // TLA-wake>          /\ s' = [s EXCEPT !.fd = [c \in Callers |-> IF c \in s.cmds THEN "taken" ELSE s.fd[c]],
    // TLA-wake>                            !.cmds = {}, !.epc = "handle"]
    // TLA-wake> \* It then does each. The descriptor of a command that is done is in the
    // TLA-wake> \* stack, or it is closed because the command was refused.
    // TLA-wake> EHandle == /\ s.epc = "handle"
    // TLA-wake>            /\ IF \E c \in Callers : s.fd[c] = "taken"
    // TLA-wake>                 THEN \E c \in Callers, to \in {"engine", "closed"} :
    // TLA-wake>                        s.fd[c] = "taken" /\ s' = [s EXCEPT !.fd[c] = to]
    // TLA-wake>                 ELSE s' = [s EXCEPT !.epc = "turn"]
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

    // TLA-wake> \* The loop turns until the thread is told to stop.
    // TLA-wake> ETop == /\ s.epc = "top"
    // TLA-wake>         /\ s' = [s EXCEPT !.epc = IF s.stop THEN "refuse" ELSE "take"]
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

    // TLA-wake> \* A turn does the thread's work, which the model leaves out, and then
    // TLA-wake> \* waits in poll.
    // TLA-wake> ETurn == /\ s.epc = "turn"
    // TLA-wake>          /\ s' = [s EXCEPT !.epc = IF Fault = "late drain" THEN "drain" ELSE "poll"]
    // TLA-wake> \* poll returns when the pipe holds a byte, and the pipe is drained only
    // TLA-wake> \* then. The drain comes before the commands are next taken. So a byte
    // TLA-wake> \* that it takes never stood for a command that is still to be seen.
    // TLA-wake> EPoll == /\ s.epc = "poll" /\ (s.pipe > 0 \/ Ticks)
    // TLA-wake>          /\ s' = [s EXCEPT !.epc = IF s.pipe > 0 /\ Fault # "late drain" THEN "drain" ELSE "top"]
    // TLA-wake> EDrain == /\ s.epc = "drain"
    // TLA-wake>           /\ s' = [s EXCEPT !.pipe = 0, !.epc = IF Fault = "late drain" THEN "poll" ELSE "top"]
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

    // TLA-wake> \* A tunnel that is told to stop takes no more commands. It then serves
    // TLA-wake> \* its connections until they have ended, or for as long as it may.
    // TLA-wake> ERefuse == /\ s.epc = "refuse" /\ s' = [Refused(s) EXCEPT !.epc = "linger"]
    // TLA-wake> ELinger == /\ s.epc = "linger" /\ s' = [s EXCEPT !.epc = "unwind"]
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

    // TLA-wake@0> \* refuse_commands holds the lock that a caller pushes under. So `dead`
    // TLA-wake@0> \* is set and the queue is emptied in one step. A command that is
    // TLA-wake@0> \* dropped closes its descriptor.
    // TLA-wake@0> Refused(t) == [t EXCEPT !.dead = TRUE, !.cmds = {},
    // TLA-wake@0>                         !.fd = [c \in Callers |-> IF c \in t.cmds THEN "closed" ELSE t.fd[c]]]
    /// Sees that no command is queued from now on, and drops those that
    /// are. A call queues a command under this lock, and only while `dead`
    /// is false, so none is left behind with its descriptor open.
    fn refuse_commands(&self) {
        let mut cmds = self.shared.cmds.lock().unwrap_or_else(|e| e.into_inner());
        self.shared.dead.store(true, Ordering::Release);
        cmds.clear();
    }
}

// TLA-wake> \* A panic unwinds from any point of the loop, and the return from run
// TLA-wake> \* does what a panic does. The commands that were taken and not yet done
// TLA-wake> \* are dropped first, and each closes its descriptor.
// TLA-wake> EPanic == /\ MayPanic /\ s.epc \in {"top", "take", "handle", "turn", "poll", "drain", "refuse", "linger"}
// TLA-wake>           /\ s' = [s EXCEPT !.epc = "unwind"]
// TLA-wake> EUnwind == /\ s.epc = "unwind"
// TLA-wake>            /\ s' = [s EXCEPT !.fd = [c \in Callers |-> IF s.fd[c] = "taken" /\ Fault # "closed by hand"
// TLA-wake>                                                         THEN "closed" ELSE s.fd[c]],
// TLA-wake>                              !.epc = "drop"]
// TLA-wake> \* Drop for Engine refuses commands, whatever ended the thread.
// TLA-wake> EDrop == /\ s.epc = "drop" /\ s' = [Refused(s) EXCEPT !.epc = "fields"]
// TLA-wake> \* The engine's fields are dropped last, and the descriptors of the stack
// TLA-wake> \* with them. The pipe is not among them: the handle is the last to hold
// TLA-wake> \* it. Suppose that the thread closed its end of the pipe here. A caller
// TLA-wake> \* may have queued a command and not yet written its byte. It would then
// TLA-wake> \* write to a pipe that nothing reads, which is SIGPIPE.
// TLA-wake> EFields == /\ s.epc = "fields"
// TLA-wake>            /\ s' = [s EXCEPT !.fd = [c \in Callers |-> IF s.fd[c] = "engine" THEN "closed" ELSE s.fd[c]],
// TLA-wake>                              !.rOpen = @ /\ Fault # "engine's pipe", !.epc = "done"]
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

// TLA-wake@90> Engine == \/ ETop \/ ETake \/ EHandle \/ ETurn \/ EPoll \/ EDrain
// TLA-wake@90>           \/ ERefuse \/ ELinger \/ EUnwind \/ EDrop \/ EFields
// TLA-wake@90> Caller(c) == CPush(c) \/ CWake(c) \/ CReturn(c)
// TLA-wake@90> Closer == KPop \/ KStop \/ KWake \/ KJoin \/ KFree \/ KReturn
// TLA-wake@90> Next == Engine \/ EPanic \/ KEnter \/ Closer \/ \E c \in Callers : CEnter(c) \/ Caller(c)
// TLA-wake@90> \* Every thread runs if it can. Nobody has to call, to close or to panic.
// TLA-wake@90> Spec == Init /\ [][Next]_s /\ WF_s(Engine) /\ WF_s(Closer) /\ \A c \in Callers : WF_s(Caller(c))
// TLA-wake@90>
// TLA-wake@90> \* No thread is in a call on a handle that has been freed.
// TLA-wake@90> NoUseAfterFree == s.freed => \A c \in Callers : s.cpc[c] \notin {"push", "wake"}
// TLA-wake@90> \* Both ends of the pipe are open when a thread is about to write to it.
// TLA-wake@90> Waking == {s.cpc[c] : c \in Callers} \cup {s.kpc}
// TLA-wake@90> PipeIsThere == "wake" \in Waking => s.rOpen /\ s.wOpen
// TLA-wake@90> \* Once the thread has ended, it holds no descriptor and none waits for it.
// TLA-wake@90> NoLeak == s.epc = "done" => \A c \in Callers : s.fd[c] \in {"none", "closed"}
// TLA-wake@90> \* The handle is freed only when the thread has ended.
// TLA-wake@90> FreedLast == s.freed => s.epc = "done"
// TLA-wake@90> \* A command leaves the queue when it is taken.
// TLA-wake@90> TakenOnce == \A c \in Callers : c \in s.cmds => s.fd[c] = "queued"
// TLA-wake@90> \* A queued command is taken, or its descriptor is closed. Without the
// TLA-wake@90> \* timer, this says that no wake is lost.
// TLA-wake@90> Taken == \A c \in Callers : s.fd[c] = "queued" ~> s.fd[c] \in {"engine", "closed"}
// TLA-wake@90> \* A tunnel that is told to stop does stop, and its closer returns.
// TLA-wake@90> Stops == s.stop ~> s.kpc = "done"
// TLA-wake@90> \* A handle that is taken out of its holder is freed.
// TLA-wake@90> Released == ~s.held ~> s.freed
// TLA-wake@90> \* A byte in the pipe is drained unless the thread is ending. So the
// TLA-wake@90> \* thread does not turn for ever for one byte.
// TLA-wake@90> Drained == s.pipe > 0 ~> s.pipe = 0 \/ s.epc \notin {"top", "take", "handle", "turn", "poll", "drain"}
//
// The model is checked without the timer, to show that no wake depends on
// it, and with a panic possible at any point.
//
// TLA-wake.cfg> SPECIFICATION Spec
// TLA-wake.cfg> CONSTANTS Callers = {c1, c2}
// TLA-wake.cfg>   PipeCap = 1
// TLA-wake.cfg>   MayPanic = TRUE
// TLA-wake.cfg>   Ticks = FALSE
// TLA-wake.cfg>   Fault = "none"
// TLA-wake.cfg> INVARIANTS NoUseAfterFree PipeIsThere NoLeak FreedLast TakenOnce
// TLA-wake.cfg> PROPERTIES Taken Stops Released Drained
// TLA-wake.cfg> CHECK_DEADLOCK FALSE
//
// It is checked with the timer too, and with a third caller.
//
// TLA-wake.cfg/ticking> Ticks = TRUE
// TLA-wake.cfg/three> Callers = {c1, c2, c3}
//
// Each of these variants has a fault that the code avoids, and the model
// finds each. The thread closes its end of the pipe as it ends:
//
// TLA-wake.cfg/engines-pipe!PipeIsThere> Fault = "engine's pipe"
//
// A command holds a bare descriptor, which the code closes where it
// remembers to, and unwinding closes nothing:
//
// TLA-wake.cfg/closed-by-hand!NoLeak> Fault = "closed by hand"
//
// The pipe is drained after the commands are taken:
//
// TLA-wake.cfg/late-drain!Taken> Fault = "late drain"
//
// Tunnel#close takes no lock:
//
// TLA-wake.cfg/no-lock!NoUseAfterFree> Fault = "no lock"
//
// Something raises between the taking of the handle and the call that
// frees it:
//
// TLA-wake.cfg/lost-handle!Released> Fault = "lost handle"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knobs_are_read_from_text() {
        assert_eq!(Knobs::parse("").unwrap(), Knobs::default());
        assert_eq!(Knobs::parse(" trace=40 ,").unwrap(), Knobs { trace: 40, ..Knobs::default() });
        let all = Knobs { trace: 1_000_000, fail: true, drop: Some((1500, Duration::from_millis(30))), sack: true };
        assert_eq!(Knobs::parse("fail,trace=5000000,drop=1500:30,sack").unwrap(), all);
        for bad in ["trace", "trace=x", "trace=-1", "loud", "trace=1,loud", "fail=1", "drop=5", "drop=a:b", "sack=0"] {
            let knob = bad.rsplit(',').next().unwrap();
            assert_eq!(Knobs::parse(bad).unwrap_err(), format!("bad debug knob {knob:?}"));
        }
    }
}

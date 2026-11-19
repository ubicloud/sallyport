//! A tunnel's thread owns the UDP socket, the WireGuard sessions and the
//! TCP stack, and serves them from one loop that never takes Ruby's GVL.

use crate::config::Config;
use crate::conn::status;
use crate::packet::describe;
use crate::peers::{Dropped, Peers};
use crate::sys;
use crate::tcp::Stack;
use std::collections::VecDeque;
use std::net::{IpAddr, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// boringtun's timers run this often.
const TICK: Duration = Duration::from_millis(250);
/// One turn of the loop takes this many datagrams from the UDP socket at
/// most. It is many because a datagram that waits in the kernel's buffer
/// is dropped when the buffer fills, and one that has been taken is not.
const UDP_BATCH: usize = 1024;

/// A command is what a call into the library asks of a tunnel's thread.
/// It carries our end of a socket pair, which is closed if the command is
/// dropped. The caller has the other end, and the thread answers on the
/// pair.
pub enum Cmd {
    Connect { fd: OwnedFd, addr: IpAddr, port: u16 },
    Listen { fd: OwnedFd, port: u16, backlog: usize },
    Tell { fd: OwnedFd, of: Of },
}

/// What a caller may ask the thread to tell of the tunnel.
#[derive(Clone, Copy)]
pub enum Of {
    /// A description of the whole tunnel, for a person to read.
    Tunnel,
    /// The state of each peer, as Peers::stats writes it.
    Peers,
    /// How many connections the tunnel has.
    Connections,
}

/// What the thread tells a caller that asked, and how much of it the
/// caller's pair has taken. It is a status of one byte, which is 0, and
/// then the text. So a caller can tell a text with nothing in it from
/// the silence of a thread that ended first.
struct Telling {
    fd: OwnedFd,
    text: Vec<u8>,
    sent: usize,
}

// The model "wake" is of what a tunnel's thread shares with the threads
// that call the library: how a call reaches the thread, how a caller is
// answered, and how the thread and its handle end. The lines of the model
// are beside the code that they describe, here and in lib.rs, and Ruby's
// part is in tunnel.rb. tools/tla gathers them, and `rake tla` checks
// them.
//
// TLA-wake@0> EXTENDS Naturals
// TLA-wake@0> CONSTANTS Callers,   \* the Ruby threads that each make one call
// TLA-wake@0>           MayPanic,  \* the tunnel's thread may panic at any point
// TLA-wake@0>           Ticks,     \* poll also returns for a timer
// TLA-wake@0>           Fault      \* the fault that a variant puts in, or "none"
// TLA-wake@0> \* The state is one record, so that a step says what it changes and no more.
// TLA-wake@0> VARIABLE s
// TLA-wake@0> Init == s = [cmds  |-> {},      \* Shared.cmds: the callers whose command is queued
// TLA-wake@0>              dead  |-> FALSE,   \* Shared.dead
// TLA-wake@0>              stop  |-> FALSE,   \* Shared.stop
// TLA-wake@0>              woken |-> FALSE,   \* the count of the eventfd is not 0
// TLA-wake@0>              open  |-> TRUE,    \* the eventfd is open
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
    /// The eventfd that wakes the loop. It is closed with the handle,
    /// which is the last to hold it, once the thread has ended.
    pub eventfd: OwnedFd,
    pub stop: AtomicBool,
    /// How many milliseconds the thread may take to end its connections
    /// in order, once it is told to stop.
    pub linger: AtomicU32,
}

// TLA-wake@0> \* Shared::wake adds to the count of the eventfd, and does not wait.
// TLA-wake@0> Woke(t) == [t EXCEPT !.woken = TRUE]
impl Shared {
    pub fn wake(&self) {
        sys::signal(self.eventfd.as_raw_fd());
    }
}

/// Knobs are settings for tests and for looking inside a tunnel. sp_open
/// takes them as text, with commas between them.
#[derive(Debug, Default, PartialEq)]
pub struct Knobs {
    /// `trace=N` keeps a line for each of the last N TCP packets, a
    /// million at most. The tunnel's description then has them, and
    /// smoltcp's account of each socket.
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
    /// The answers that are not yet written whole.
    telling: Vec<Telling>,
    next_tick: Instant,
    /// A command or a packet has given the stack cause for a turn.
    stirred: bool,
    /// When the stack next has a timer, as it said after its last turn.
    stack_due: Option<Instant>,
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
    /// sys::udp_socket returns it, and the eventfd that wakes it. An error
    /// is a fault in the configuration.
    pub fn new(
        cfg: &Config,
        knobs: Knobs,
        (udp, udp_v6): (UdpSocket, bool),
        eventfd: OwnedFd,
        set: OwnedFd,
    ) -> Result<(Engine, Arc<Shared>), String> {
        let peers = Peers::new(cfg)?;
        let shared = Arc::new(Shared {
            cmds: Mutex::default(),
            dead: AtomicBool::new(false),
            eventfd,
            stop: AtomicBool::new(false),
            linger: AtomicU32::new(0),
        });
        let engine = Engine {
            shared: shared.clone(),
            udp,
            udp_v6,
            peers,
            stack: Stack::new(cfg, knobs.sack, set),
            telling: Vec::new(),
            next_tick: Instant::now(),
            stirred: true,
            stack_due: None,
            buf: vec![0; 65536],
            datagrams: 0,
            packets: 0,
            knobs,
            trace: VecDeque::new(),
            epoch: Instant::now(),
            drop_until: None,
        };
        Ok((engine, shared))
    }

    // TLA-wake> \* The thread takes every queued command at once, under the lock.
    // TLA-wake> ETake == /\ s.epc = "take"
    // TLA-wake>          /\ s' = [s EXCEPT !.fd = [c \in Callers |-> IF c \in s.cmds THEN "taken" ELSE s.fd[c]],
    // TLA-wake>                            !.cmds = {}, !.epc = "handle"]
    // TLA-wake> \* It then does each. The thread keeps the descriptor of a command that
    // TLA-wake> \* is done, for as long as it has more to send on it, or closes it.
    // TLA-wake> EHandle == /\ s.epc = "handle"
    // TLA-wake>            /\ IF \E c \in Callers : s.fd[c] = "taken"
    // TLA-wake>                 THEN \E c \in Callers, to \in {"engine", "closed"} :
    // TLA-wake>                        s.fd[c] = "taken" /\ s' = [s EXCEPT !.fd[c] = to]
    // TLA-wake>                 ELSE s' = [s EXCEPT !.epc = "turn"]
    /// Takes the commands that have been queued, and does each.
    fn commands(&mut self) {
        let cmds = std::mem::take(&mut *self.shared.cmds.lock().unwrap_or_else(|e| e.into_inner()));
        for cmd in cmds {
            self.stirred |= !matches!(cmd, Cmd::Tell { .. });
            match cmd {
                Cmd::Connect { fd, addr, port } if self.peers.reaches(&addr) => self.stack.connect(fd, addr, port),
                Cmd::Connect { fd, .. } => Stack::refuse(fd, status::NO_ROUTE),
                Cmd::Listen { fd, port, backlog } => self.stack.listen(fd, port, backlog),
                Cmd::Tell { fd, of } => {
                    // The length goes before the text, so that a caller
                    // can tell an answer that was cut short from a whole
                    // one. The thread may end before it has written all.
                    let told = self.tell_of(of);
                    let text = [&[status::OK][..], &(told.len() as u32).to_be_bytes(), told.as_bytes()].concat();
                    self.telling.push(Telling { fd, text, sent: 0 });
                }
            }
        }
    }

    /// Writes as much of each answer as its pair takes now. An answer
    /// that is written whole is dropped, which ends the stream that the
    /// caller reads. So is one whose caller has closed its end.
    fn tell(&mut self) {
        self.telling.retain_mut(|telling| {
            while telling.sent < telling.text.len() {
                match sys::send(telling.fd.as_raw_fd(), &telling.text[telling.sent..]) {
                    n if n > 0 => telling.sent += n as usize,
                    0 | sys::AGAIN => return true,
                    _ => return false,
                }
            }
            false
        });
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
            let from = sys::udp_from(from);
            let (udp, v6) = (&self.udp, self.udp_v6);
            let packet = self.peers.receive(&self.buf[..len], from, &mut |d, to| sys::udp_send(udp, v6, d, to));
            if let Some(packet) = packet {
                self.trace("in ", &packet);
                self.stack.receive(packet);
                self.stirred = true;
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
    // TLA-wake> ETurn == s.epc = "turn" /\ s' = [s EXCEPT !.epc = IF Fault = "late drain" THEN "drain" ELSE "poll"]
    // TLA-wake> \* poll returns when the count of the eventfd is not 0, and the count is
    // TLA-wake> \* set to 0 only then. That comes before the commands are next taken. So
    // TLA-wake> \* a wake that it clears never stood for a command that is still to be
    // TLA-wake> \* seen.
    // TLA-wake> EPoll == /\ s.epc = "poll" /\ (s.woken \/ Ticks)
    // TLA-wake>          /\ s' = [s EXCEPT !.epc = IF s.woken /\ Fault # "late drain" THEN "drain" ELSE "top"]
    // TLA-wake> EDrain == /\ s.epc = "drain"
    // TLA-wake>           /\ s' = [s EXCEPT !.woken = FALSE, !.epc = IF Fault = "late drain" THEN "poll" ELSE "top"]
    /// Makes one turn of the loop. It takes what has arrived, moves the
    /// connections, sends what they have to send, and then waits until
    /// there is more to do, or for `most` at the longest.
    fn serve(&mut self, fds: &mut Vec<libc::pollfd>, most: Duration) {
        let more = self.udp_in();
        let ticked = Instant::now() >= self.next_tick;
        if ticked {
            self.tick();
            self.next_tick = Instant::now() + TICK;
        }
        // The stack has a turn when something concerns it: a packet or a
        // command, a pair that poll reported, a timer of its own, or the
        // tick, at which it looks at every connection. A datagram that
        // carried no packet for it is no such thing. Anyone can send
        // those, and a turn costs time for each socket that the stack
        // has.
        let reported = fds.get(2).is_none_or(|set| set.revents != 0);
        let due = self.stack_due.is_some_and(|at| Instant::now() >= at);
        if self.stirred || reported || due || ticked {
            self.stirred = false;
            self.stack.turn();
            self.flush();
            self.stack_due = self.stack.poll_delay().map(|delay| Instant::now() + delay);
        }
        self.tell();

        let mut wait = self.next_tick.saturating_duration_since(Instant::now()).min(most);
        if let Some(at) = self.stack_due {
            wait = wait.min(at.saturating_duration_since(Instant::now()));
        }
        // The turn left each connection at rest, and poll reports what
        // moves one on. Only the datagrams that were not taken do not
        // wait.
        if more {
            wait = Duration::ZERO;
        }
        fds.clear();
        fds.extend(
            [self.shared.eventfd.as_raw_fd(), self.udp.as_raw_fd(), self.stack.poll_fd()].map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            }),
        );
        // An answer waits for room in its pair, or for its caller to
        // close the other end.
        fds.extend(self.telling.iter().map(|telling| libc::pollfd {
            fd: telling.fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        }));
        if !sys::poll(fds, wait) {
            // poll could not look, which a signal does to it now and
            // then, and a limit of the process may do each time. The
            // loop goes on as if everything were reported, and does not
            // spin.
            fds.clear();
            std::thread::sleep(wait.min(Duration::from_millis(10)));
        }
        if fds.first().is_some_and(|eventfd| eventfd.revents != 0) {
            sys::drain(self.shared.eventfd.as_raw_fd());
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

    /// Returns what a caller asked the thread to tell.
    fn tell_of(&self, of: Of) -> String {
        match of {
            Of::Tunnel => self.describe(),
            Of::Peers => {
                let mut text = String::new();
                self.peers.stats(&mut text);
                text
            }
            Of::Connections => format!("{}\n", self.stack.connections()),
        }
    }

    /// Describes the tunnel for a person who wants to know why something
    /// does not move.
    fn describe(&self) -> String {
        assert!(!self.knobs.fail, "the tunnel's thread was told to fail");
        let Dropped { unknown, refused, disallowed } = self.peers.dropped;
        let mut text = format!(
            "{} datagrams in: {unknown} from no peer, {refused} refused, {disallowed} from a source not allowed\n\
             {} packets out\n\
             peers, each with its endpoint, the milliseconds since its handshake, and the bytes sent and received:\n",
            self.datagrams, self.packets
        );
        self.peers.stats(&mut text);
        self.stack.describe(&mut text, self.knobs.trace > 0);
        if self.knobs.trace > 0 {
            text += "the last TCP packets, each with the seconds since the tunnel started:\n";
            for line in &self.trace {
                text += line;
                text += "\n";
            }
        }
        text
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
            self.stirred = true;
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
// TLA-wake> \* The engine's fields are dropped last, and the descriptors that the
// TLA-wake> \* thread keeps with them. The eventfd is not among them: the handle is
// TLA-wake> \* the last to hold it. Suppose that the thread closed the eventfd here. A
// TLA-wake> \* caller may have queued a command and not yet woken the thread. It
// TLA-wake> \* would then write to a descriptor that is closed, or that is another's
// TLA-wake> \* by then.
// TLA-wake> EFields == /\ s.epc = "fields"
// TLA-wake>            /\ s' = [s EXCEPT !.fd = [c \in Callers |-> IF s.fd[c] = "engine" THEN "closed" ELSE s.fd[c]],
// TLA-wake>                              !.open = @ /\ Fault # "thread closes", !.epc = "done"]
/// The thread ends when run returns, or with a panic. Either way the
/// engine is dropped, and every descriptor that the thread holds is
/// closed with it. Ruby's ends then reach end of file, so a tunnel that
/// has failed looks closed to Ruby, and not silent.
impl Drop for Engine {
    fn drop(&mut self) {
        self.refuse_commands();
    }
}

// TLA-wake@90> Engine == \/ ETop \/ ETake \/ EHandle \/ ETurn \/ EPoll \/ EDrain
// TLA-wake@90>           \/ ERefuse \/ ELinger \/ EUnwind \/ EDrop \/ EFields
// TLA-wake@90> Caller(c) == CPush(c) \/ CWake(c) \/ CReturn(c)
// TLA-wake@90> Closer == KPop \/ KStop \/ KWake \/ KJoin \/ KFree \/ KReturn
// TLA-wake@90> Next == \/ Engine \/ EPanic \/ KEnter \/ Closer
// TLA-wake@90>         \/ \E c \in Callers : CEnter(c) \/ Caller(c)
// TLA-wake@90> \* Every thread runs if it can. Nobody has to call, to close or to panic.
// TLA-wake@90> Spec == /\ Init /\ [][Next]_s /\ WF_s(Engine) /\ WF_s(Closer)
// TLA-wake@90>         /\ \A c \in Callers : WF_s(Caller(c))
// TLA-wake@90>
// TLA-wake@90> \* No thread is in a call on a handle that has been freed.
// TLA-wake@90> NoUseAfterFree == s.freed => \A c \in Callers : s.cpc[c] \notin {"push", "wake"}
// TLA-wake@90> \* The eventfd is open when a thread is about to write to it.
// TLA-wake@90> Waking == {s.cpc[c] : c \in Callers} \cup {s.kpc}
// TLA-wake@90> WakeIsOpen == "wake" \in Waking => s.open
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
// TLA-wake@90> \* The count of the eventfd is set to 0 unless the thread is ending. So
// TLA-wake@90> \* the thread does not turn for ever for one wake.
// TLA-wake@90> Drained == s.woken ~> ~s.woken \/ s.epc \notin {"top", "take", "handle", "turn", "poll", "drain"}
//
// The model is checked without the timer, to show that no wake depends on
// it, and with a panic possible at any point.
//
// TLA-wake.cfg> SPECIFICATION Spec
// TLA-wake.cfg> CONSTANTS Callers = {c1, c2}
// TLA-wake.cfg>   MayPanic = TRUE
// TLA-wake.cfg>   Ticks = FALSE
// TLA-wake.cfg>   Fault = "none"
// TLA-wake.cfg> INVARIANTS NoUseAfterFree WakeIsOpen NoLeak FreedLast TakenOnce
// TLA-wake.cfg> PROPERTIES Taken Stops Released Drained
// TLA-wake.cfg> CHECK_DEADLOCK FALSE
//
// It is checked with the timer too, and with a third caller.
//
// TLA-wake.cfg/ticking> Ticks = TRUE
// TLA-wake.cfg/three> Callers = {c1, c2, c3}
//
// Each of these variants has a fault that the code avoids, and the model
// finds each. The thread closes the eventfd as it ends:
//
// TLA-wake.cfg/thread-closes!WakeIsOpen> Fault = "thread closes"
//
// A command holds a bare descriptor, which the code closes where it
// remembers to, and unwinding closes nothing:
//
// TLA-wake.cfg/closed-by-hand!NoLeak> Fault = "closed by hand"
//
// The count of the eventfd is set to 0 after the commands are taken:
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

    /// The model "wake" takes this much of an eventfd.
    #[test]
    fn an_eventfd_wakes_poll_from_the_first_wake_until_it_is_drained() {
        let eventfd = sys::eventfd().unwrap();
        let woken = || sys::revents(eventfd.as_raw_fd(), libc::POLLIN) & libc::POLLIN != 0;
        assert!(!woken());
        sys::signal(eventfd.as_raw_fd());
        sys::signal(eventfd.as_raw_fd());
        assert!(woken());
        sys::drain(eventfd.as_raw_fd());
        assert!(!woken());
    }

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

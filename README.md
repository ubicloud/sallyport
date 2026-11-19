# sallyport

sallyport puts a WireGuard interface inside a Ruby process. There is no
TUN device, no routing table and no privilege: all that the system sees
of a tunnel is a UDP socket. A TCP connection through the tunnel is a
socket with a descriptor of its own, so `IO.select`, OpenSSL and Net::SSH
use it as they use any other socket.

```ruby
require "sallyport"
require "net/ssh"

tunnel = Sallyport::Tunnel.new(File.read("wg0.conf"))

socket = tunnel.connect("10.9.0.1", 80)
socket.write("GET / HTTP/1.0\r\n\r\n")
puts socket.read

Net::SSH.start("10.9.0.1", "admin", proxy: tunnel) { |ssh| puts ssh.exec!("uptime") }

listener = tunnel.listen(8080)
client = listener.accept
puts client.remote_address.ip_address

tunnel.close
```

A tunnel takes a configuration in the format of wg-quick(8), as above, or
the parts of one:

```ruby
key = Sallyport.private_key
puts Sallyport.public_key(key)

tunnel = Sallyport::Tunnel.new(
  private_key: key,
  addresses: ["10.9.0.2", "fd09::2"],
  peers: [{
    public_key: "the peer's public key",
    endpoint: "198.51.100.7:51820",
    allowed_ips: ["10.9.0.0/24", "fd09::/64"],
    persistent_keepalive: 25
  }]
)
tunnel.peers.each { |peer| puts "#{peer.public_key} #{peer.alive?}" }
```

## How it is made

The gem is a Rust library behind a C ABI of eleven functions, which Ruby
binds by hand with Fiddle. [boringtun](https://github.com/cloudflare/boringtun)
is its WireGuard and [smoltcp](https://github.com/smoltcp-rs/smoltcp) is
its TCP. The repository holds a copy of each in `ext/sallyport/vendor`,
and the library is built with those. `ext/sallyport/vendor/README.md`
says where each copy is from, and `tools/deviations` lists what has been
changed in each, by class. To install the gem is to build the library,
which takes Cargo.

Each tunnel has a thread of its own, which never takes the GVL. The
thread owns the UDP socket, the WireGuard sessions and the TCP stack.

Each connection is a Unix socket pair. Ruby holds one end, and that is the
descriptor that it selects on and gives to OpenSSL. The thread holds the
other end, and moves bytes between it and the TCP socket. Both have
bounded buffers, so each direction has flow control from end to end.

No call into the library waits for the tunnel's thread, but the call
that closes the tunnel. `connect` gets a descriptor at once, and the
outcome arrives on it as its first byte. So Ruby waits in its own I/O,
where a timeout or an interrupt can reach it. A listener is a socket pair
too, of the kind that keeps messages apart. Each connection arrives on it
as a message that carries the connection's descriptor. `peers`,
`connections` and `dump` each get a descriptor as well, and read the
thread's answer from it.

## What it does not do

- It carries TCP, over IPv4 and IPv6, and nothing else. It does not
  answer a ping.
- It is written for Linux.
- A tunnel does not survive fork. Make it in the process that uses it. If
  a child is forked while a tunnel is open, it has copies of the tunnel's
  descriptors. Until the child ends or calls exec, the UDP port stays
  bound, and the sockets of the parent do not reach end of file when the
  tunnel closes.
- An exception from another thread, as `Thread#kill` and `Timeout` raise
  one, cannot leave a tunnel or a descriptor without an owner. Ruby does
  not hold back the exception of a signal in the same way, so Ctrl-C can,
  at the moment that a tunnel is made or closed, or a connection is begun
  or accepted.
- `Tunnel#close` waits for its linger, and nothing ends that wait
  sooner. An exception from another thread waits with it. So does a
  signal, if the main thread is the one that closes. Every other call on
  the tunnel waits for the close as well.
- `connect` takes an IP address, because a tunnel has no resolver. The
  host name of a peer's endpoint is resolved once, when the tunnel starts.
- A `Sallyport::Socket` is a `UNIXSocket`. Its `remote_address` is the
  peer's address and port. Its `local_address` is not an address of the
  tunnel, and a TCP option that is set on it has no effect.
- A reset from the peer reads as the end of the stream, where a TCP socket
  of the kernel raises `Errno::ECONNRESET`. It reads as `ECONNRESET` here
  only if the socket still held bytes that the tunnel had not taken. A
  write after a reset raises `Errno::EPIPE`.
- A socket that has shut down its reading, with `close_read`, goes on
  writing. What the peer sends to it from then on stays in the tunnel,
  64 KiB of it at the most, and the peer is held after that. If the
  socket is closed while the tunnel holds such bytes, the peer is reset.
- It agrees to no selective acknowledgement. The last section says why.
- It does not delay an ACK, as most TCPs do to send it with data. An ACK
  leaves in the turn of the tunnel's thread that took the segments in,
  and one ACK answers all that the turn took in. So a segment that
  arrives alone has an ACK to itself, where most TCPs send one ACK for
  two segments. Segments that arrive faster than the thread turns share
  an ACK.
- A connection that has ended leaves no socket to wait in TIME-WAIT. Its
  last ACK has left by the end of the turn that ends it. If that ACK is
  lost, the peer sends its FIN again, and is answered with a reset where
  a kernel sends the ACK again. Neither side has lost a byte by then.
- The window that it gives a peer has no scale, so a peer sends 64 KiB
  at the most in one round trip. Where a round trip takes 100 ms, Ruby
  reads 640 KiB a second at the most. The last section says why.
- A listener's backlog is 128 connections at most.
- A tunnel answers a peer from the address that the system chooses for
  the way back. On a machine with several addresses, that may not be the
  address that the peer wrote to, and a NAT or a firewall on the peer's
  side may then drop the answer. The kernel's WireGuard answers from the
  address that it was written to.
- A connection has 320 KiB of buffers from its first packet on, and
  keeps them until it has ended. A socket that Ruby has closed can take
  a while to end: up to 60 seconds if the peer does not end its stream,
  and up to 300 if the peer is gone. The tunnel's thread holds a
  descriptor for it as long. If the process cannot have the memory for
  a buffer, it ends, as a Rust program does when an allocation fails.
- It is made for tens or hundreds of connections in a tunnel, and not
  for thousands. A connection that nothing happens to costs the tunnel's
  thread no system call. But smoltcp looks at every socket for each
  packet that arrives, and for each round of packets that leave. Beside
  1,000 idle connections, a busy one carries a sixth of what it carries
  alone, and a byte takes six times as long to go and to come back.

## Looking inside

`Tunnel#peers` gives each peer's endpoint, the age of its last handshake
and its byte counts. `Tunnel#connections` counts the connections.
`Tunnel#dump` returns a description of the tunnel for a person to read,
with a line for each connection.

A tunnel's packets are encrypted on the wire, so tcpdump shows nothing of
the TCP inside. With `SALLYPORT_DEBUG=trace=200` in the environment, or
`debug: "trace=200"` given to `Tunnel.new`, the tunnel keeps a line for
each of its last 200 TCP packets, and `Tunnel#dump` returns them. It
then also returns the account that smoltcp gives of each connection's
socket. That account takes the tunnel's thread some 6 ms for each
connection, in which the tunnel does nothing else.

## Tests

| Command | What it runs | What it takes |
| --- | --- | --- |
| `rake test` | The unit tests of the library, and the Ruby tests, in which two tunnels of one process are each other's peer. | Cargo |
| `rake slow` | The unit tests that wait for a timer of WireGuard or of TCP to run out. | Cargo |
| `rake fixtures` | Builds Wireproxy, an SSH server and `kernelpeer` into `tmp/bin`. The tests that need them are skipped without them. | Go |
| `rake test TEST=test/test_ring.rb` | The tests against Wireproxy, which is wireguard-go with the netstack of gVisor. | `rake fixtures` |
| `sudo env "PATH=$PATH" ruby -Ilib -Itest test/test_kernel.rb` | The tests against the TCP of the Linux kernel, behind wireguard-go in a network namespace. | `rake fixtures`, root |
| `rake vpp`, then `sudo env "PATH=$PATH" ruby -Ilib -Itest test/test_vpp.rb` | The tests against VPP, which the task fetches as packages for Ubuntu 24.04. | root, ethtool |
| `rake tla` | TLC on the TLA+ models. The task fetches TLC. | Java |
| `rake conform` | The code that moves the bytes of a connection, in every state that TLC reaches of the model of it. | Java, Cargo |
| `rake vendored` | The tests that smoltcp and boringtun have of their own, on the copies in `ext/sallyport/vendor`. First `rake deviations` checks that each change of a copy is of a deviation that has a class. | Cargo, the whole history |

The tests against another implementation put it in a ring. A test writes
to a connection that it made, and reads the same bytes from a connection
that it accepted. So every byte has crossed the other implementation
twice, once with each side as the TCP client. CI runs all of the above
on each push.

The script `bench/bench.rb` prints rough numbers for a machine. They are
the throughput of a connection, the time that a byte takes to go and
another to come back, and what idle tunnels cost. `bench/delay.rb` prints
the throughput of a path that takes time, which a relay between the
tunnels makes.

## Models

Three parts of the library are easier to get wrong than to test, and
each has a TLA+ model. The model `wake` is of what a tunnel's thread
shares with the threads that call the library: how a call reaches the
thread, how a caller is answered, and how the thread and its handle end.
The model `listen` is of one listener: which SYN gets a socket, how many
connections may wait for Ruby, and what becomes of a SYN that arrives
twice or finds no room. The model `conn` is of one connection for the
whole of its life: how Ruby is answered when it makes one, and how it is
handed one that a peer made, how bytes move between Ruby's descriptor
and the TCP socket, what `poll` is asked about the descriptor, and how
the connection ends.

`conn` stands on three more modules. `stream` is what a connection
promises to Ruby and to the peer, with no word of sockets or
descriptors: no byte is lost unless the connection is cut, a stream ends
once, after its last byte, and a connection is cut only for a cause.
`pair` is what the library takes for granted of the kernel's socket
pair, and `sock` is what it takes for granted of smoltcp's socket. Tests
hold the kernel and smoltcp to those two. TLC checks that `conn` then
keeps the promise, whatever Ruby and the peer do, and with Ruby free to
act between any two system calls that the library makes on the pair.
`listen` stands in the same way on `ctl`, which is what the library takes
for granted of a listener's socket pair.

The code is held to `conn` as the kernel is held to `pair`. `carry` is
the function that moves the bytes of an open connection and decides how
the connection ends. It makes a pass in four steps, and the model has
the same four. `rake conform` has TLC write what the model says of each
state of an open connection that it reaches: what `poll` is asked there,
and the state after a whole pass, or after the step that the state is
at. A unit test gives `carry`, or that step, a pair and a socket that are
records of the model, in each of those states, and the outcome must be
the one that the model has. In the model Ruby acts between two steps, so
each step is run in the states that Ruby can bring about before it. A
change that makes `carry` do otherwise than the model says fails that
test. The test holds `shake` to the model in the same way, which is the
function that decides what has become of a handshake.

A model is written in the source, as comments beside the code that each
line describes:

```rust
// TLA-wake> \* The wake comes after the lock is let go. The thread may have taken the
// TLA-wake> \* command by then, and may even have ended.
// TLA-wake> CWake(c) == /\ s.cpc[c] = "wake" /\ s' = Woke([s EXCEPT !.cpc[c] = "return"])
```

`tools/tla` gathers the lines of each model into a module and runs TLC on
it. Its first lines say how the comments are written. A model has
variants, and most of them have a fault that the code avoids. TLC must
find the fault in each, which shows that the model can.

The configurations in the source are small, so that CI checks them in a
few minutes. For a larger one, change the constants in the lines that
begin `TLA-conn.cfg>` or `TLA-wake.cfg>`, or run `rake tla:extract` and
give TLC a configuration of your own beside the modules in `tmp/tla`.
`TLC_OPTS` and `JAVA_OPTS` pass options to TLC and to Java.

## What the other implementations showed

The tests against other implementations, and the models, found the
following. Each is something that another project may want to know of,
and most name the test that shows it.

smoltcp, at the commit that `ext/sallyport/vendor/README.md` names:

- Release 0.14.0 panics when a peer fills a receive window whose edge the
  window scale rounded back. The fix is on the main branch and in no
  release, which is why a commit is named.
- A window that has a scale is rounded down to it, so the end of the
  window moves back by a few bytes as the buffer fills. A segment is
  taken as far as the end that the socket has on record, which its last
  ACK gave. If the peer sent as far as an earlier end, the last bytes of
  the segment are dropped and its FIN is taken all the same. The program
  then reads the end of the stream without those bytes. While the window
  is shut, nothing from that peer counts as heard, and the timeout
  resets a peer that is there. This library gives a window of 65535
  bytes, which has no scale
  (`a_stream_that_ends_where_the_window_ends_is_read_whole`,
  `a_peer_that_has_filled_a_shut_window_is_still_heard`).
- A keep-alive carries the window as it is when it is sent, and so does
  a probe of a window that the peer has shut. The socket keeps no record
  that it gave a window in either. If a peer takes the window from such
  a segment, it may send further than the socket takes. Linux takes it
  from a keep-alive that follows data. There too the FIN of a segment
  that was cut is taken. This library gives smoltcp a FIN in a packet of
  its own, after the data
  (`a_fin_is_not_taken_with_a_segment_that_the_window_cut`).
- A socket's timeout counts the time since the peer's last packet,
  whether or not anything waits to be acknowledged. A connection that is
  only quiet is reset unless a keep-alive is set as well
  (`a_quiet_connection_stays_open_until_its_peer_is_gone`).
- When TIME-WAIT is over, the socket is cleared, and with it the bytes
  that the program has not yet read
  (`what_ruby_has_not_read_outlasts_time_wait`).
- A probe of a shut window can carry the FIN with the last byte. If the
  peer takes that and keeps its window shut, the timer of the probe stays
  set with nothing to send. The socket then sends an ACK at every
  dispatch, and `Interface::poll` does not return. A peer can stop a
  program that way (`a_fin_does_not_ride_on_the_probe_of_a_shut_window`).
- In LAST-ACK the socket answers an ACK that acknowledges nothing new
  with a challenge ACK, and does not take the window that the ACK carries.
  So it learns that a window which had shut is open again only from its
  next probe (`a_fin_waits_for_a_peer_that_ended_first_to_take_the_data`).
- A reset in SYN-RECEIVED puts a socket that had listened back in LISTEN.
  A program that makes a socket for each SYN has to remove it then
  (`a_handshake_that_its_peer_resets_leaves_no_socket`).
- `connect` to an IPv6 address, from an interface that has no IPv6
  address, sends from the loopback address
  (`an_address_that_the_tunnel_cannot_connect_from_has_no_route`).
- Every SYN offers selective acknowledgement, and no setting turns the
  offer off. The socket reports one block at most, and as a sender it
  makes no use of the blocks that it is sent
  (`a_syn_offers_selective_acknowledgement_only_if_the_stack_is_told_to`).
- A socket has no congestion control unless one is chosen, and its
  retransmission timer is never less than a second unless that is set
  (`a_socket_has_the_settings_that_the_stack_gives`).

The netstack of gVisor, in Wireproxy 1.1.3:

- When a transfer from netstack loses a whole flight of segments, it
  resumes with two segments at each timeout, and the timeouts double. It
  does this only on a connection that agreed to selective acknowledgement.
  With an outage of 30 ms, a transfer of 6 MiB took more than 25 seconds.
  It took 0.3 seconds once the offer was taken out of the SYNs
  (`test_a_transfer_from_wireproxy_gets_past_an_outage`).

Wireproxy 1.1.3:

- It does not pass on the end of one direction of a connection. When
  either direction ends, it closes both
  (`test_wireproxy_ends_both_directions_when_one_ends`).

VPP 26.10:

- With checksum offload, which is the default, a TCP segment that leaves
  through VPP's WireGuard fails authentication at the peer. The setting
  `tcp { no-csum-offload }` mends that for every segment but a reset
  (`test_a_reset_from_vpp_does_not_arrive`).
- Its test proxy does not pass on the end of one direction either
  (`test_vpp_ends_both_directions_when_one_ends`).

Ruby 3.3:

- `Thread.handle_interrupt` does not hold back the exception that a
  signal raises in the main thread, such as `Interrupt`.
- A thread can be left to wait for a Mutex that is free. Mutex wakes one
  thread that waits when it is unlocked. If that thread is killed before
  it runs, no other is woken, and a thread that waits with its interrupts
  held off then keeps a process from its exit. So `Tunnel#connect` and
  `Tunnel#listen` hold off interrupts only once they have the lock.

boringtun 0.7.1:

- It gives a handshake up after 90 seconds, and begins another only when
  it is given a packet to send. Its timers report the expiry before they
  come to the persistent keepalive, so a peer with a keepalive is not
  tried again (`a_peer_with_a_keepalive_is_tried_for_as_long_as_it_is_silent`).
- A program can check the MACs of a handshake first, so that it spends
  no key exchange on a message that fails them. boringtun then checks them
  again, because its function for a message that is already checked is
  not public.
- Its limiter asks for a cookie when handshake messages come fast, and
  bounds nothing more. A sender that has a cookie is taken at any rate,
  and each message costs a key exchange. The tunnel holds each source
  address to a rate while it is under load, as the kernel's WireGuard
  does (`a_source_with_a_cookie_is_held_to_a_rate_under_load`).
- It does not pad a packet, and its source says that this is still to
  do. WireGuard pads each packet with zeros to a multiple of 16 bytes,
  so that the length of a datagram says less of what it carries. The
  tunnel pads the packet before boringtun has it
  (`a_packet_is_padded_to_sixteen_bytes_and_arrives_as_it_was`).
- It keeps the session of each initiation that it answers in one of
  eight places, and sends in the session that is in the place of the
  current one, whether or not the peer has confirmed it. WireGuard sends
  in a session only when the peer has shown that it holds the keys.
  After eight initiations that their sender does not complete, as with a
  preshared key that does not match, the peer reads as alive, and
  packets for it leave in a session that it does not have. The tunnel
  does nothing about this.
- A session lasts 180 seconds, and boringtun begins the next one when it
  has something to send and none to send it in. A peer that sends only
  keepalives, every 25 seconds, is without a session for some 20 seconds
  in every 200, and `Peer#alive?` is false then. The first packet brings
  a handshake, which takes a few milliseconds. The kernel's WireGuard
  begins the next session while the old one still holds.
- It does not look at what a key exchange gives. A few public keys give
  zeros with every private key, and a session with such a peer would have
  keys that anyone can make. The tunnel refuses a configuration that has
  one as a peer's key
  (`a_peer_may_not_have_a_key_that_makes_no_secret`).

## License

The library is under the Apache License 2.0, which is in `LICENSE`. The
two directories in `ext/sallyport/vendor` are not: each is a copy of
another project, and is under that project's license, which the
directory holds. smoltcp is under 0BSD, and boringtun under the BSD
3-Clause license. When this repository changes something in such a
directory, the change is under the license of the directory.

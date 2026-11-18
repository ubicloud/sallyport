# frozen_string_literal: true

# This prints how fast a connection carries bytes over a path that takes
# time. Both tunnels are in this process, and each is the other's peer. A
# relay in a process of its own holds each datagram between them for the
# delay.
#
#   ruby bench/delay.rb 10 32
#
# That is a delay of 10 ms each way, and 32 MiB to send. A transfer is
# slower at its start, so a smaller size gives a smaller number. The relay
# is written in Ruby, and on a fast path it is the relay that the numbers
# measure. So it says how late a datagram left it at the worst, counted
# from when the relay read the datagram.

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sallyport"
require "socket"

$stdout.sync = true

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

# Sends what arrives on `near` to the port `to` after the delay, and sends
# what comes back to the port `from`. It ends when the pipe from its
# parent does.
def relay(near, to, from, delay, parent)
  far = UDPSocket.new
  far.connect("127.0.0.1", to)
  near.connect("127.0.0.1", from)
  # A burst is more than a socket holds as it is made, and the relay would
  # drop part of it. Root may go past the limit that the system sets.
  [near, far].each do |socket|
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUFFORCE, 8 << 20)
  rescue Errno::EPERM
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 8 << 20)
  end
  other = {near => far, far => near}
  held = []
  late = 0
  loop do
    while held.first && held.first[0] <= (time = now)
      due, out, data = held.shift
      late = [late, time - due].max
      out.send(data, 0)
    end
    ready, = IO.select([near, far, parent], nil, nil, held.first && [held.first[0] - now, 0].max)
    due = now + delay
    ready&.each do |socket|
      if socket == parent
        puts format("relay       %.1f ms late at the worst", late * 1e3)
        return
      end
      while (data = socket.recv_nonblock(65_536, exception: false)).is_a?(String)
        held << [due, other[socket], data]
      end
    end
  end
end

delay = Float(ARGV.fetch(0)) / 1000
size = Integer(ARGV.fetch(1)) << 20

# A tunnel does not survive fork, so the relay is forked before there is
# one, and is told later where the two tunnels listen. It ends without a
# word if its parent ends before that.
near = UDPSocket.new
near.bind("127.0.0.1", 0)
from_parent, to_relay = IO.pipe
relay_pid = fork do
  to_relay.close
  ports = from_parent.gets or exit
  relay(near, *ports.split.map { |port| Integer(port) }, delay, from_parent)
end
from_parent.close

a_key, b_key = Sallyport.private_key, Sallyport.private_key
a_is = {public_key: Sallyport.public_key(a_key), allowed_ips: ["fd09::1/128"]}
b_is = {public_key: Sallyport.public_key(b_key), allowed_ips: ["fd09::2/128"]}
a = Sallyport::Tunnel.new(private_key: a_key, addresses: ["fd09::1"], peers: [b_is])
b = Sallyport::Tunnel.new(private_key: b_key, addresses: ["fd09::2"],
                          peers: [a_is.merge(endpoint: "127.0.0.1:#{near.addr[1]}")])
to_relay.puts("#{a.listen_port} #{b.listen_port}")
near.close
listener = a.listen(7000)
client = b.connect("fd09::1", 7000)
server = listener.accept

trips = Array.new(5) do
  start = now
  client.write("k")
  server.readpartial(1)
  server.write("k")
  client.readpartial(1)
  now - start
end

chunk = "x" * (1 << 16)
start = now
writer = Thread.new { (size / chunk.bytesize).times { client.write(chunk) } }
got = 0
got += server.readpartial(1 << 20).bytesize while got < size
writer.join
took = now - start
puts format("round trip  %.1f ms, for one byte each way", trips.min * 1e3)
puts format("throughput  %.2f MiB/s, for %d MiB one way", size / took / (1 << 20), size >> 20)
to_relay.close
Process.wait(relay_pid)
[a, b].each { |tunnel| tunnel.close(linger: 0) }

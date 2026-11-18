# frozen_string_literal: true

# This prints rough numbers for one machine: how fast a connection
# carries bytes, how long a small write takes to come back, and what
# tunnels cost when nothing happens. Both tunnels are in this process, and
# each is the other's peer.
#
#   ruby bench/bench.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sallyport"

def cpu_seconds
  times = Process.times
  times.utime + times.stime
end

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

a_key, b_key = Sallyport.private_key, Sallyport.private_key
a_is = {public_key: Sallyport.public_key(a_key), allowed_ips: ["fd09::1/128"]}
b_is = {public_key: Sallyport.public_key(b_key), allowed_ips: ["fd09::2/128"]}
a = Sallyport::Tunnel.new(private_key: a_key, addresses: ["fd09::1"], peers: [b_is])
b = Sallyport::Tunnel.new(private_key: b_key, addresses: ["fd09::2"],
                          peers: [a_is.merge(endpoint: "127.0.0.1:#{a.listen_port}")])
listener = a.listen(7000)
client = b.connect("fd09::1", 7000)
server = listener.accept

size = 256 << 20
chunk = "x" * (1 << 16)
start = now
writer = Thread.new { (size / chunk.bytesize).times { client.write(chunk) } }
got = 0
got += server.readpartial(1 << 20).bytesize while got < size
writer.join
puts format("throughput  %.0f MiB/s, for %d MiB one way", size / (now - start) / (1 << 20), size >> 20)

times = Array.new(2000) do
  start = now
  client.write("k")
  server.readpartial(1)
  server.write("k")
  client.readpartial(1)
  now - start
end.sort
puts format("echo        %.0f us at the median and %.0f us at the 99th percentile, for one byte each way",
            times[times.size / 2] * 1e6, times[times.size * 99 / 100] * 1e6)

idle = Array.new(20) { [b.connect("fd09::1", 7000), listener.accept] }
before = cpu_seconds
sleep 5
puts format("idle        %.2f%% of a CPU, for two tunnels and %d open connections",
            (cpu_seconds - before) / 5 * 100, idle.size + 1)
[a, b].each(&:close)

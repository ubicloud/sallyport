# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sallyport"
require "minitest/autorun"
require "io/nonblock"
require "socket"
require "timeout"

module Helper
  # Returns the path of a fixture, which is a program that "rake fixtures"
  # builds, or nil if it is not built.
  def self.fixture(name)
    path = File.expand_path("../tmp/bin/#{name}", __dir__)
    path if File.executable?(path)
  end

  # A test is skipped for want of a fixture, but not where every test is
  # meant to run. CI says so with this variable, and a skip fails there.
  def skip(message = nil, *)
    ENV["SALLYPORT_NO_SKIP"] ? flunk("not run: #{message}") : super
  end

  # A test that hangs fails here, and does not hold the run until CI
  # gives it up.
  def run
    Timeout.timeout(60) { super }
  end

  def setup
    @closers = []
  end

  # Every closer runs, whatever an earlier one raised.
  def teardown
    errors = []
    @closers.reverse_each do |closer|
      closer.call
    rescue StandardError => e
      errors << e
    end
    raise errors.first unless errors.empty?
  end

  # Returns a private key and its public key.
  def keypair
    private_key = Sallyport.private_key
    [private_key, Sallyport.public_key(private_key)]
  end

  # Starts a tunnel that is closed when the test ends.
  def tunnel(...)
    t = Sallyport::Tunnel.new(...)
    @closers << -> { t.close }
    t
  end

  # Starts two tunnels that are each other's peer: a at 10.9.0.1 and
  # fd09::1, and b at 10.9.0.2 and fd09::2. Only b is told where its peer
  # is, and +peer+ adds to what b is told of it. Both tunnels take the
  # settings in +debug+.
  def pair(debug: nil, **peer)
    (a_key, a_public), (b_key, b_public) = keypair, keypair
    a_is = {public_key: a_public, allowed_ips: ["10.9.0.1/32", "fd09::1/128"]}
    b_is = {public_key: b_public, allowed_ips: ["10.9.0.2/32", "fd09::2/128"]}
    a = tunnel(private_key: a_key, addresses: ["10.9.0.1", "fd09::1"], peers: [b_is], debug: debug)
    b_peer = a_is.merge(endpoint: "127.0.0.1:#{a.listen_port}", **peer)
    [a, tunnel(private_key: b_key, addresses: ["10.9.0.2", "fd09::2"], peers: [b_peer], debug: debug)]
  end

  # Connects b to a listener on a, and returns the Socket at each end:
  # b's first.
  def connection(a, b, to: "10.9.0.1")
    listener = a.listen(7)
    client = b.connect(to, 7)
    server = listener.accept(timeout: 5)
    listener.close
    @closers << -> { [client, server].each(&:close) }
    [client, server]
  end

  # Waits until the block returns a true value, and returns it. Fails the
  # test if that takes more than +within+ seconds.
  def eventually(within: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + within
    until (value = yield)
      flunk "it did not happen in #{within} seconds" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.02
    end
    value
  end

  # A fixture runs under a shell that holds the reading end of a pipe
  # from this process, and that kills the fixture when the pipe closes.
  # So a run of the tests that is killed leaves no fixture behind.
  # The shell says nothing of a fixture that it killed.
  LEASH = '"$@" & fixture=$!; read -r _ <&9; exec 2>/dev/null; kill "$fixture"; wait "$fixture"'

  # Starts a fixture that is stopped when the test ends.
  def spawn_fixture(*command, **options)
    leash, hold = IO.pipe
    # Ruby makes its pipes non-blocking, and the shell's read would not
    # wait on one.
    leash.nonblock = false
    pid = Process.spawn("sh", "-c", LEASH, "fixture", *command, 9 => leash, **options)
    leash.close
    @closers << lambda {
      hold.close
      Process.wait(pid)
    }
    pid
  end

  # Returns a TCP port on the loopback interface that was free a moment
  # ago.
  def free_tcp_port
    server = TCPServer.new("127.0.0.1", 0)
    server.addr[1]
  ensure
    server&.close
  end

  # Waits until something accepts connections on a loopback port.
  def wait_for_tcp(port)
    eventually do
      TCPSocket.new("127.0.0.1", port).close
      true
    rescue Errno::ECONNREFUSED
      false
    end
  end

  # Writes +data+ to one socket while it reads as much from another, and
  # returns what it read.
  def transfer(from, to, data)
    writer = Thread.new { from.write(data) }
    got = +""
    got << to.readpartial(1 << 20) while got.bytesize < data.bytesize
    writer.join
    got
  end

  # Returns a UDP port that was free a moment ago.
  def free_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    socket.addr[1]
  ensure
    socket&.close
  end
end

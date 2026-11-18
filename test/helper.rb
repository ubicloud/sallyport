# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sallyport"
require "minitest/autorun"
require "socket"
require "timeout"

module Helper
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
  # is, and +peer+ adds to what b is told of it.
  def pair(**peer)
    (a_key, a_public), (b_key, b_public) = keypair, keypair
    a_is = {public_key: a_public, allowed_ips: ["10.9.0.1/32", "fd09::1/128"]}
    b_is = {public_key: b_public, allowed_ips: ["10.9.0.2/32", "fd09::2/128"]}
    a = tunnel(private_key: a_key, addresses: ["10.9.0.1", "fd09::1"], peers: [b_is])
    b_peer = a_is.merge(endpoint: "127.0.0.1:#{a.listen_port}", **peer)
    [a, tunnel(private_key: b_key, addresses: ["10.9.0.2", "fd09::2"], peers: [b_peer])]
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

  # Returns a UDP port that was free a moment ago.
  def free_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    socket.addr[1]
  ensure
    socket&.close
  end
end

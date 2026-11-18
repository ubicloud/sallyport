# frozen_string_literal: true

require_relative "helper"
require "digest"
require "tempfile"

# These tests have a third TCP at the other end, that of the Linux kernel,
# which is what an sshd behind a tunnel has. The fixture is wireguard-go on
# a TUN device in a network namespace of its own, with a forwarder on
# kernel sockets. It makes the ring that Wireproxy makes: its port 7000
# leads back to port 7001 here.
#
# A namespace and a TUN device take privilege, so the tests are skipped
# where there is none.
class TestKernel < Minitest::Test
  include Helper

  KERNELPEER = Helper.fixture("kernelpeer")

  def setup
    super
    skip "there is no kernelpeer: run `rake fixtures`" unless KERNELPEER
    skip "the kernel's ring takes root and /dev/net/tun" unless Process.uid.zero? && File.exist?("/dev/net/tun")
  end

  # Starts a tunnel and the fixture, and makes a connection round the
  # ring. Returns the tunnel, the end that connected, the end that
  # accepted, and the fixture's address in the family that the kernel has.
  def around(debug: nil)
    (key, public), (their_key, their_public) = keypair, keypair
    peer = {public_key: their_public, allowed_ips: ["10.7.0.2/32", "fd07::2/128"]}
    t = tunnel(private_key: key, addresses: ["10.7.0.1", "fd07::1"], peers: [peer], debug: debug)
    listener = t.listen(7001)
    log = Tempfile.new(["kernelpeer", ".log"])
    @closers << -> { log.close! }
    said, says = IO.pipe
    spawn_fixture(KERNELPEER, their_key, public, "127.0.0.1:#{t.listen_port}", out: says, err: log.path)
    says.close
    ready = said.gets if said.wait_readable(10)
    flunk "the fixture did not come up, and said:\n#{File.read(log.path)}" unless ready&.start_with?("ready")
    theirs = ready.end_with?("6\n") ? "fd07::2" : "10.7.0.2"
    eventually { t.peers.first.alive? }
    client = t.connect(theirs, 7000, timeout: 5)
    server = listener.accept(timeout: 5)
    assert_equal theirs, server.remote_address.ip_address
    @closers << -> { [client, server, listener].each(&:close) }
    [t, client, server, theirs]
  end

  def test_bytes_go_round_the_ring
    _, client, server = around
    client.write("ping")
    assert_equal "ping", server.readpartial(16)
    server.write("pong")
    assert_equal "pong", client.readpartial(16)
  end

  # The kernel passes on the end of one direction, as Wireproxy does not.
  def test_each_direction_ends_on_its_own
    t, client, server = around
    client.write("question")
    client.close_write
    assert_equal "question", server.read
    server.write("answer")
    server.close
    assert_equal "answer", client.read
    client.close
    eventually { t.connections.zero? }
  end

  def test_a_large_transfer_each_way_at_once
    _, client, server = around
    up, down = Random.new(8).bytes(6 << 20), Random.new(9).bytes(6 << 20)
    back = Thread.new { transfer(server, client, down) }
    assert_equal Digest::SHA256.hexdigest(up), Digest::SHA256.hexdigest(transfer(client, server, up))
    assert_equal Digest::SHA256.hexdigest(down), Digest::SHA256.hexdigest(back.value)
  end

  def test_a_port_where_the_kernel_does_not_listen_refuses
    t, _, _, theirs = around
    assert_raises(Errno::ECONNREFUSED) { t.connect(theirs, 9, timeout: 5) }
  end

  def test_a_transfer_from_the_kernel_gets_past_an_outage
    _, client, server = around(debug: "drop=1500:30")
    data = Random.new(10).bytes(6 << 20)
    assert_equal Digest::SHA256.hexdigest(data), Digest::SHA256.hexdigest(transfer(server, client, data))
  end
end

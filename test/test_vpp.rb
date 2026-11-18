# frozen_string_literal: true

require_relative "helper"
require "digest"
require "fileutils"
require "tmpdir"

# These tests have VPP at the other end, which has a WireGuard and a TCP
# that no other test has. Its proxy makes the ring: port 7000 there leads
# back to port 7001 here.
#
# VPP wants an interface for itself. So the kernel has one end of a veth
# pair at 10.99.7.1, VPP has the other end at 10.99.7.2 by AF_PACKET, and
# the tunnel reaches VPP's WireGuard across the pair. The names and the
# addresses are fixed, so one run at a time can have them. VPP needs no
# hugepages and no DPDK for this.
#
# The tests are skipped where there is no VPP, which `rake vpp` fetches,
# and where the user is not root.
class TestVPP < Minitest::Test
  include Helper

  ROOT = File.expand_path("../tmp/vpp/root", __dir__)
  # The packages put the libraries in a directory that the architecture
  # names.
  LIB = Dir[File.join(ROOT, "usr/lib/*/vpp_plugins")].map { |plugins| File.dirname(plugins) }.first
  HOST, VPP, PORT = "10.99.7.1", "10.99.7.2", 51_820

  def setup
    super
    skip "there is no VPP: run `rake vpp`" unless LIB
    skip "VPP takes root" unless Process.uid.zero?
    skip "the fixture takes ip and ethtool" unless quiet("ip", "-V") && quiet("ethtool", "--version")
  end

  def quiet(*command)
    system(*command, out: File::NULL, err: File::NULL)
  end

  def sh(*command)
    quiet(*command) or flunk "this failed: #{command.join(" ")}"
  end

  # Starts VPP as the only peer of a tunnel that has this public key and
  # this UDP port. VPP is 10.7.0.2 inside the tunnel. Returns the path of
  # what VPP says.
  def vpp(private_key, peer_public_key, peer_port)
    dir = Dir.mktmpdir("sallyport-vpp")
    @closers << -> { FileUtils.rm_rf(dir) }
    quiet("ip", "link", "del", "sp-host")
    sh("ip", "link", "add", "sp-host", "type", "veth", "peer", "name", "sp-vpp")
    @closers << -> { quiet("ip", "link", "del", "sp-host") }
    sh("ip", "addr", "add", "#{HOST}/30", "dev", "sp-host")
    sh("ip", "link", "set", "sp-host", "up")
    sh("ip", "link", "set", "sp-vpp", "up")
    # The kernel leaves the checksum of what it sends on a veth device to
    # be made later, and nothing makes it on the way to VPP.
    sh("ethtool", "-K", "sp-host", "tx", "off")

    File.write(File.join(dir, "startup.conf"), <<~CONF)
      unix { nodaemon cli-listen #{dir}/cli.sock runtime-dir #{dir} exec #{dir}/setup.vpp }
      plugins {
        path #{LIB}/vpp_plugins
        plugin default { disable }
        plugin af_packet_plugin.so { enable }
        plugin wireguard_plugin.so { enable }
        plugin hs_apps_plugin.so { enable }
      }
      memory { main-heap-size 512M main-heap-page-size 4K }
      buffers { buffers-per-numa 16384 page-size 4K }
      statseg { size 32M page-size 4K socket-name #{dir}/stats.sock }
      socksvr { socket-name #{dir}/api.sock }
      # Without this setting no TCP segment from VPP arrives. Each is a
      # datagram that fails authentication, as a reset still is: see the
      # test of one.
      tcp { no-csum-offload }
    CONF
    File.write(File.join(dir, "setup.vpp"), <<~CLI)
      create host-interface name sp-vpp
      set interface state host-sp-vpp up
      set interface ip address host-sp-vpp #{VPP}/30
      wireguard create listen-port #{PORT} private-key #{private_key} src #{VPP}
      set interface state wg0 up
      set interface ip address wg0 10.7.0.2/32
      wireguard peer add wg0 public-key #{peer_public_key} endpoint #{HOST} allowed-ip 10.7.0.1/32 dst-port #{peer_port} persistent-keepalive 25
      ip route add 10.7.0.1/32 via wg0
      session enable
      test proxy server server-uri tcp://10.7.0.2/7000 client-uri tcp://10.7.0.1/7001 fifo-size 512k
    CLI
    log = File.join(dir, "vpp.log")
    spawn_fixture("env", "LD_LIBRARY_PATH=#{LIB}", File.join(ROOT, "usr/bin/vpp"), "-c", File.join(dir, "startup.conf"),
                  out: log, err: %i[child out])
    log
  end

  # Starts a tunnel and VPP, and makes a connection round the ring.
  # Returns the tunnel, the end that connected and the end that accepted.
  # VPP's proxy connects back when the first bytes reach it, so some are
  # written.
  def around(debug: nil)
    (key, public), (their_key, their_public) = keypair, keypair
    peer = {public_key: their_public, endpoint: "#{VPP}:#{PORT}", allowed_ips: ["10.7.0.2/32"]}
    t = tunnel(private_key: key, addresses: ["10.7.0.1"], peers: [peer], debug: debug)
    listener = t.listen(7001)
    log = vpp(their_key, public, t.listen_port)
    begin
      eventually { t.peers.first.alive? }
    rescue Minitest::Assertion
      flunk "VPP did not come up, and said:\n#{File.read(log)}"
    end
    client = t.connect("10.7.0.2", 7000, timeout: 5)
    @closers << -> { client.close }
    client.write("hello")
    server = listener.accept(timeout: 5)
    @closers << -> { [server, listener].each(&:close) }
    assert_equal "10.7.0.2", server.remote_address.ip_address
    assert_equal "hello", server.read(5)
    [t, client, server]
  end

  def test_bytes_go_round_the_ring
    _, client, server = around
    server.write("pong")
    assert_equal "pong", client.readpartial(16)
    client.write("ping")
    assert_equal "ping", server.readpartial(16)
  end

  def test_a_large_transfer_each_way_at_once
    _, client, server = around
    up, down = Random.new(11).bytes(6 << 20), Random.new(12).bytes(6 << 20)
    back = Thread.new { transfer(server, client, down) }
    assert_equal Digest::SHA256.hexdigest(up), Digest::SHA256.hexdigest(transfer(client, server, up))
    assert_equal Digest::SHA256.hexdigest(down), Digest::SHA256.hexdigest(back.value)
  end

  def test_the_end_of_a_connection_goes_round
    _, client, server = around
    client.write("last words")
    client.close
    assert_equal "last words", server.read
  end

  # VPP's proxy does not pass on the end of one direction either: when
  # one ends, it closes both.
  def test_vpp_ends_both_directions_when_one_ends
    _, client, server = around
    client.write("question")
    client.close_write
    assert_equal "question", server.read
    assert_equal "", client.read
  end

  # VPP answers a SYN to a port where nothing listens with a reset, and
  # the reset does not arrive. VPP's trace shows the packet leave with the
  # checksum of its IP header still owed ("offload-ip-cksum"), at an
  # offset that is by then inside the ciphertext, and the tunnel counts a
  # datagram that fails authentication for each reset. So the connection
  # times out where it would be refused. This is what VPP 26.10 does. A
  # version that mends it fails this test, which then wants a refusal.
  def test_a_reset_from_vpp_does_not_arrive
    t, = around
    assert_raises(Errno::ETIMEDOUT) { t.connect("10.7.0.2", 9, timeout: 2) }
    assert_match(/, [1-9]\d* refused,/, t.dump.lines.first)
  end

  def test_a_transfer_from_vpp_gets_past_an_outage
    _, client, server = around(debug: "drop=1500:30")
    data = Random.new(13).bytes(6 << 20)
    assert_equal Digest::SHA256.hexdigest(data), Digest::SHA256.hexdigest(transfer(server, client, data))
  end
end

# frozen_string_literal: true

require_relative "helper"
require "digest"
require "net/ssh"
require "openssl"
require "tempfile"

# These tests have a second implementation at the other end: Wireproxy,
# which is wireguard-go and the netstack of gVisor, in user space as well.
#
# One Wireproxy carries a ring. Its TCPServerTunnel listens inside the
# tunnel and forwards to a port on the loopback interface. Its
# TCPClientTunnel listens on that port and forwards back into the tunnel:
#
#   connect --WireGuard--> Wireproxy:7000 --loopback--> Wireproxy --WireGuard--> accept
#
# So what this process writes to a connection that it made comes back on
# one that it accepted, and every byte has crossed each implementation
# twice, once with each as the TCP client.
class TestRing < Minitest::Test
  include Helper

  WIREPROXY = Helper.fixture("wireproxy")
  SSHD = Helper.fixture("sshd")

  def setup
    super
    skip "there is no Wireproxy: run `rake fixtures`" unless WIREPROXY
  end

  # Starts a tunnel and a Wireproxy that are each other's only peer: the
  # tunnel at 10.7.0.1 and fd07::1, Wireproxy at 10.7.0.2 and fd07::2.
  # +sections+ is the rest of Wireproxy's configuration. The tunnel is not
  # told where Wireproxy is, and learns it from the handshake that
  # Wireproxy's keepalive has it begin.
  def ring(sections, debug: nil)
    (key, public), (their_key, their_public) = keypair, keypair
    peer = {public_key: their_public, allowed_ips: ["10.7.0.2/32", "fd07::2/128"]}
    t = tunnel(private_key: key, addresses: ["10.7.0.1", "fd07::1"], peers: [peer], debug: debug)
    conf = Tempfile.new(["wireproxy", ".conf"])
    @closers << -> { conf.close! }
    conf.write(<<~CONF + sections)
      [Interface]
      Address = 10.7.0.2/32, fd07::2/128
      PrivateKey = #{their_key}

      [Peer]
      PublicKey = #{public}
      Endpoint = 127.0.0.1:#{t.listen_port}
      AllowedIPs = 10.7.0.1/32, fd07::1/128
      PersistentKeepalive = 25

    CONF
    conf.flush
    # Wireproxy reports every connection that ends. What it says is kept
    # for the case that it does not come up.
    log = Tempfile.new(["wireproxy", ".log"])
    @closers << -> { log.close! }
    spawn_fixture(WIREPROXY, "-c", conf.path, "-s", out: log.path, err: log.path)
    begin
      eventually { t.peers.first.alive? }
    rescue Minitest::Assertion
      flunk "Wireproxy did not shake hands, and said:\n#{File.read(log.path)}"
    end
    assert_match(/\A127\.0\.0\.1:\d+\z/, t.peers.first.endpoint)
    t
  end

  # Makes a ring through a tunnel's address of a family, and a connection
  # round it. Returns the tunnel, the end that connected, the end that
  # accepted, and the listener.
  def around(family, debug: nil)
    theirs, ours = (family == 6) ? ["fd07::2", "[fd07::1]:7001"] : ["10.7.0.2", "10.7.0.1:7001"]
    loopback = free_tcp_port
    t = ring(<<~CONF, debug: debug)
      [TCPServerTunnel]
      ListenPort = 7000
      Target = 127.0.0.1:#{loopback}

      [TCPClientTunnel]
      BindAddress = 127.0.0.1:#{loopback}
      Target = #{ours}
    CONF
    listener = t.listen(7001)
    # To see that Wireproxy listens, a connection is made to it, which
    # goes half way round the ring.
    wait_for_tcp(loopback)
    listener.accept(timeout: 5).close
    client = t.connect(theirs, 7000, timeout: 5)
    server = listener.accept(timeout: 5)
    assert_equal theirs, server.remote_address.ip_address
    @closers << -> { [client, server, listener].each(&:close) }
    [t, client, server, listener]
  end

  def test_bytes_go_round_the_ring
    [4, 6].each do |family|
      _, client, server = around(family)
      client.write("ping")
      assert_equal "ping", server.readpartial(16)
      server.write("pong")
      assert_equal "pong", client.readpartial(16)
    end
  end

  def test_a_large_transfer_each_way_at_once
    _, client, server = around(6)
    up, down = Random.new(4).bytes(6 << 20), Random.new(5).bytes(6 << 20)
    back = Thread.new { transfer(server, client, down) }
    assert_equal Digest::SHA256.hexdigest(up), Digest::SHA256.hexdigest(transfer(client, server, up))
    assert_equal Digest::SHA256.hexdigest(down), Digest::SHA256.hexdigest(back.value)
  end

  # The outage takes a whole flight of the segments that Wireproxy sends.
  # With selective acknowledgement agreed, netstack then sends two
  # segments at each of its timeouts and no more, and this takes minutes.
  def test_a_transfer_from_wireproxy_gets_past_an_outage
    _, client, server = around(6, debug: "drop=1500:30")
    data = Random.new(6).bytes(6 << 20)
    assert_equal Digest::SHA256.hexdigest(data), Digest::SHA256.hexdigest(transfer(server, client, data))
  end

  # Wireproxy does not pass on the end of one direction: when either ends,
  # it closes both. So a close goes round the ring, and a shutdown of
  # writing alone does not.
  def test_a_close_goes_round_the_ring
    t, client, server = around(4)
    client.write("last words")
    client.close
    assert_equal "last words", server.read
    server.close
    eventually { t.connections.zero? }
  end

  # Wireproxy does not pass on the end of one direction: when either
  # ends, it closes both. So the end of the stream comes back where an
  # answer could have. A Wireproxy that mends this fails the test.
  def test_wireproxy_ends_both_directions_when_one_ends
    _, client, server = around(4)
    client.write("question")
    client.close_write
    assert_equal "question", server.read
    assert_equal "", client.read
  end

  def test_many_connections_at_once
    t, _, _, listener = around(4)
    message = ->(i) { "stream #{i} " * 2000 }
    size = message.call(10).bytesize
    servers = Thread.new do
      Array.new(16) do
        Thread.new(listener.accept(timeout: 10)) do |server|
          server.write(server.read(size).upcase)
          # The client closes when it has its answer.
          server.read
          server.close
        end
      end.each(&:join)
    end
    clients = Array.new(16) do |i|
      Thread.new do
        client = t.connect("10.7.0.2", 7000, timeout: 10)
        client.write(message.call(10 + i))
        client.read(size).tap { client.close }
      end
    end
    clients.each_with_index { |client, i| assert_equal message.call(10 + i).upcase, client.value }
    servers.join
  end

  def test_a_port_that_wireproxy_does_not_forward_refuses
    t = ring("[TCPServerTunnel]\nListenPort = 7000\nTarget = 127.0.0.1:9\n")
    assert_raises(Errno::ECONNREFUSED) { t.connect("10.7.0.2", 7999, timeout: 5) }
  end

  # The server is an ordinary one on the loopback interface, which
  # Wireproxy forwards to, and its TLS ends in this process at both ends.
  def test_tls_to_a_server_behind_wireproxy
    key = OpenSSL::PKey::EC.generate("prime256v1")
    name = OpenSSL::X509::Name.parse("/CN=sallyport")
    cert = OpenSSL::X509::Certificate.new
    cert.version, cert.serial, cert.subject, cert.issuer, cert.public_key = 2, 1, name, name, key
    cert.not_before, cert.not_after = Time.now - 60, Time.now + 600
    cert.sign(key, "SHA256")
    tcp = TCPServer.new("127.0.0.1", 0)
    @closers << -> { tcp.close }
    served = Thread.new do
      context = OpenSSL::SSL::SSLContext.new
      context.cert, context.key = cert, key
      tls = OpenSSL::SSL::SSLSocket.new(tcp.accept, context).accept
      tls.write(tls.readpartial(64).reverse)
      tls.close
    end
    t = ring("[TCPServerTunnel]\nListenPort = 443\nTarget = 127.0.0.1:#{tcp.addr[1]}\n")
    tls = OpenSSL::SSL::SSLSocket.new(t.connect("fd07::2", 443, timeout: 5)).connect
    assert_equal cert.to_der, tls.peer_cert.to_der
    tls.write("over tls")
    assert_equal "slt revo", tls.read
    served.join
  end

  # Net::SSH takes the tunnel for its proxy, and reaches an SSH server
  # that Wireproxy forwards to.
  def test_net_ssh_through_a_tunnel
    skip "there is no SSH server: run `rake fixtures`" unless SSHD
    port = free_tcp_port
    spawn_fixture(SSHD, "127.0.0.1:#{port}")
    wait_for_tcp(port)
    t = ring("[TCPServerTunnel]\nListenPort = 22\nTarget = 127.0.0.1:#{port}\n")
    options = {
      proxy: t, password: "sallyport", auth_methods: ["password"], timeout: 5, non_interactive: true,
      verify_host_key: :never, config: false, user_known_hosts_file: File::NULL, global_known_hosts_file: File::NULL
    }
    said = Net::SSH.start("fd07::2", "anyone", **options) { |ssh| ssh.exec!("uname -a") }
    assert_equal "ran: uname -a\n", said
    eventually { t.connections.zero? }
  end
end

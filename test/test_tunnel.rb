# frozen_string_literal: true

require_relative "helper"
require "ipaddr"

class TestTunnel < Minitest::Test
  include Helper

  # Returns what a tunnel says of a configuration that it refuses.
  def fault(...)
    assert_raises(ArgumentError) { Sallyport::Tunnel.new(...) }.message
  end

  def test_a_tunnel_holds_its_udp_port_until_it_is_closed
    key, = keypair
    parts = {private_key: key, addresses: ["10.9.0.1"], listen_port: free_udp_port}
    t = tunnel(**parts)
    refute t.closed?
    e = assert_raises(Errno::EADDRINUSE) { Sallyport::Tunnel.new(**parts) }
    assert_match(/ - UDP port #{parts[:listen_port]}\z/, e.message)
    t.close
    assert t.closed?
    tunnel(**parts)
    t.close
  end

  # The library reads the configuration while other threads run. Eight
  # megabytes of comments take it long enough for another thread to clear
  # the caller's String meanwhile. If the library read that String, the
  # test would end in a segmentation fault.
  def test_a_configuration_may_change_while_the_tunnel_is_made
    key, = keypair
    text = Sallyport::Tunnel.config(private_key: key, addresses: ["10.9.0.1"]) + ("# a line that says nothing\n" * 300_000)
    5.times do
      # A copy would share the memory of the String that it was made
      # from. This one has its own.
      conf = String.new(capacity: text.bytesize) << text
      wiper = Thread.new do
        sleep 0.001
        conf.clear
      end
      t = Sallyport::Tunnel.new(conf)
      wiper.join
      assert_operator t.listen_port, :>, 0
      t.close
    end
  end

  # Runs the block with an exception of another thread waiting, as one
  # waits while a call into the library is under way, and returns what
  # the block gave before the exception was raised.
  def interrupted
    given = nil
    assert_raises(Timeout::Error) do
      Thread.handle_interrupt(Timeout::Error => :never) do
        Thread.current.raise(Timeout::Error, "from another thread")
        given = yield
      end
    end
    given
  end

  def test_a_tunnel_whose_maker_is_interrupted_is_closed
    key, = keypair
    parts = {private_key: key, addresses: ["10.9.0.1"], listen_port: free_udp_port}
    assert interrupted { Sallyport::Tunnel.new(**parts) }.closed?
    # Its UDP port is free at once, with no wait for the collector.
    tunnel(**parts)
  end

  def test_a_listener_whose_maker_is_interrupted_leaves_its_port_free
    key, = keypair
    t = tunnel(private_key: key, addresses: ["10.9.0.1"])
    # The listener was closed, and so its maker cannot read how it fared.
    assert_nil interrupted { assert_raises(IOError) { t.listen(7) } && nil }
    eventually { t.listen(7) }.close
  end

  def test_a_tunnel_tells_its_port
    key, = keypair
    port = free_udp_port
    assert_equal port, tunnel(private_key: key, addresses: ["10.9.0.1"], listen_port: port).listen_port
    assert_operator tunnel(private_key: key, addresses: ["10.9.0.1"]).listen_port, :>, 0
  end

  def test_a_peer_before_its_handshake
    key, = keypair
    _, first = keypair
    _, second = keypair
    peers = [{public_key: first, endpoint: "127.0.0.1:9", allowed_ips: ["10.9.0.2/32"]}, {public_key: second}]
    t = tunnel(private_key: key, addresses: ["10.9.0.1"], peers: peers)
    assert_equal [[first, "127.0.0.1:9", nil, 0, 0], [second, nil, nil, 0, 0]], t.peers.map(&:to_a)
    assert_equal [Encoding::UTF_8] * 2, t.peers.first.first(2).map(&:encoding)
    refute t.peers.first.alive?
    t.close
    assert_raises(IOError) { t.peers }
  end

  # The tunnel's thread answers with nothing for a tunnel that has no
  # peer, and that is not the silence of a thread that has failed.
  def test_a_tunnel_with_no_peer
    key, = keypair
    t = tunnel(private_key: key, addresses: ["10.9.0.1"])
    assert_empty t.peers
    assert_equal 0, t.connections
  end

  # b's keepalive has it shake hands with a at once. a was not told where
  # b is, and learns it from the handshake.
  def test_two_tunnels_shake_hands
    (a_key, a_public), (b_key, b_public) = keypair, keypair
    a = tunnel(private_key: a_key, addresses: ["10.9.0.1"], peers: [{public_key: b_public, allowed_ips: ["10.9.0.2/32"]}])
    # b is not there yet, so its handshake cannot have come.
    assert_nil a.peers.first.endpoint
    a_is = {public_key: a_public, allowed_ips: ["10.9.0.1/32"], endpoint: "127.0.0.1:#{a.listen_port}"}
    b = tunnel(private_key: b_key, addresses: ["10.9.0.2"], peers: [a_is.merge(persistent_keepalive: 25)])
    eventually { a.peers.first.alive? && b.peers.first.alive? }
    assert_equal "127.0.0.1:#{b.listen_port}", a.peers.first.endpoint
    assert_operator b.peers.first.handshake_age, :<, 10
  end

  def test_a_configuration_for_wg_quick
    key, = keypair
    _, peer = keypair
    tunnel(<<~CONF)
      [Interface]
      PrivateKey = #{key}
      Address = 10.9.0.1/24, fd09::1/64  # a comment
      MTU = 1280
      DNS = 10.9.0.53

      [Peer]
      PublicKey = #{peer}
      Endpoint = localhost:51820
      AllowedIPs = 10.9.0.0/24, fd09::/64
      PersistentKeepalive = 25
    CONF
  end

  def test_a_fault_in_the_configuration
    key, = keypair
    text = "[Interface]\nPrivateKey = #{key}\nAddress = 10.9.0.1\nColour = red"
    assert_equal "line 4: unknown key colour", fault(text)
    assert_equal "line 2: a key must be 32 bytes in base64", fault(private_key: "short", addresses: ["10.9.0.1"])
    assert_equal "a tunnel has from 1 to 8 addresses", fault(private_key: key, addresses: [])
    peer = {public_key: key, allowed_ips: ["10.9.0.2/32"]}
    parts = {private_key: key, addresses: ["10.9.0.1"], peers: [peer, peer]}
    assert_equal "two peers have the same PublicKey", fault(**parts)
    assert_match(/line break/, fault(private_key: key, addresses: ["10.9.0.1\nMTU = 1"]))
    assert_match(/NUL/, fault("#{text}\0"))
    assert_raises(TypeError) { Sallyport::Tunnel.new(51_820) }
    assert_equal 'bad debug knob "loud"', fault(text.sub(/\nColour.*/, ""), debug: "trace=5,loud")
    assert_raises(TypeError) { Sallyport::Tunnel.new(text, debug: 5) }
    assert_raises(ArgumentError) { Sallyport::Tunnel.new(text, private_key: key, addresses: ["10.9.0.1"]) }
  end

  def test_the_parts_of_a_configuration
    key, = keypair
    parts = {private_key: key, addresses: [IPAddr.new("10.9.0.1")], listen_port: 51_820, mtu: 1280}
    peer = {public_key: key, endpoint: "192.0.2.1:51820", allowed_ips: [IPAddr.new("10.9.0.0/24"), "fd09::/64"]}
    assert_equal <<~CONF.chomp, Sallyport::Tunnel.config(**parts, peers: [peer.merge(persistent_keepalive: 25)])
      [Interface]
      PrivateKey = #{key}
      Address = 10.9.0.1/32
      ListenPort = 51820
      MTU = 1280
      [Peer]
      PublicKey = #{key}
      Endpoint = 192.0.2.1:51820
      AllowedIPs = 10.9.0.0/24, fd09::/64
      PersistentKeepalive = 25
    CONF
    ["10.9.0.2/32, 0.0.0.0/0", "10.9.0.2/32 # and no more"].each do |allowed|
      assert_raises(ArgumentError) { Sallyport::Tunnel.config(**parts, peers: [peer.merge(allowed_ips: [allowed])]) }
    end
  end

  def test_a_tunnel_has_one_owner
    key, = keypair
    t = tunnel(private_key: key, addresses: ["10.9.0.1"])
    assert_raises(TypeError) { t.dup }
    assert_raises(TypeError) { t.clone }
    # A copy that had the finalizer would close the tunnel here.
    GC.start
    refute t.closed?
    t.close
    t.close
    assert t.closed?
  end
end

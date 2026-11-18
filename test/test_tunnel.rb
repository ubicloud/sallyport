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

# frozen_string_literal: true

require_relative "helper"
require "rbconfig"

class TestTCP < Minitest::Test
  include Helper

  def test_a_port_where_nothing_listens_refuses
    _, b = pair
    ["10.9.0.1", "fd09::1"].each do |host|
      e = assert_raises(Errno::ECONNREFUSED) { b.connect(host, 7) }
      assert_match(/ - #{host} port 7\z/, e.message)
    end
    e = assert_raises(Errno::ECONNREFUSED) { b.connect("::ffff:10.9.0.1", 7) }
    assert_match(/ - 10\.9\.0\.1 port 7\z/, e.message)
  end

  def test_an_address_that_no_peer_takes_is_unreachable
    _, b = pair
    assert_raises(Errno::ENETUNREACH) { b.connect("10.9.9.9", 7) }
    assert_raises(Errno::ENETUNREACH) { b.connect("fd09::9", 7) }
  end

  # a was not told where b is, so its SYN goes nowhere.
  def test_a_peer_that_does_not_answer_times_out
    a, = pair
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(Errno::ETIMEDOUT) { a.connect("10.9.0.2", 7, timeout: 0.2) }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :>=, 0.2
  end

  def test_what_is_not_an_address_or_not_a_port
    a, = pair
    assert_raises(SocketError) { a.connect("example.com", 7) }
    assert_raises(SocketError) { a.connect("10.9.0.2/32", 7) }
    assert_raises(ArgumentError) { a.connect("10.9.0.2", 0) }
    assert_raises(ArgumentError) { a.connect("10.9.0.2", 65_536) }
    assert_raises(ArgumentError) { a.connect("10.9.0.2", "ssh") }
    assert_raises(ArgumentError) { a.connect("10.9.0.2", 22.5) }
    assert_equal 22, Sallyport::Tunnel.port("022")
  end

  def test_closing_a_tunnel_ends_an_attempt
    a, = pair
    attempt = Thread.new { a.connect("10.9.0.2", 7) }
    attempt.report_on_exception = false
    sleep 0.01 until attempt.status == "sleep"
    a.close
    assert_raises(IOError) { attempt.value }
    assert_raises(IOError) { a.connect("10.9.0.2", 7) }
  end

  def test_a_listener_accepts_a_connection
    a, b = pair
    {"10.9.0.1" => "10.9.0.2", "fd09::1" => "fd09::2"}.each do |to, from|
      listener = a.listen(7)
      client = b.connect(to, 7)
      assert IO.select([listener], nil, nil, 5)
      server = listener.accept
      assert_instance_of Sallyport::Socket, server
      assert_equal [a, a, b], [listener, server, client].map(&:tunnel)
      assert_equal [to, 7], [client.remote_address.ip_address, client.remote_address.ip_port]
      assert_equal from, server.remote_address.ip_address
      assert_operator server.remote_address.ip_port, :>=, 49_152
      [client, server, listener].each(&:close)
    end
  end

  def test_accept_waits_no_longer_than_its_timeout
    a, = pair
    assert_nil a.listen(7).accept(timeout: 0.05)
  end

  def test_a_port_has_one_listener_at_a_time
    a, = pair
    listener = a.listen(7)
    assert_equal 7, listener.port
    e = assert_raises(Errno::EADDRINUSE) { a.listen(7) }
    assert_match(/ - TCP port 7\z/, e.message)
    listener.close
    assert listener.closed?
    a.listen(7)
    assert_raises(ArgumentError) { a.listen(0) }
  end

  def test_a_closed_listener_refuses
    a, b = pair
    a.listen(7).close
    assert_raises(Errno::ECONNREFUSED) { b.connect("10.9.0.1", 7) }
  end

  def test_a_connection_over_the_backlog_is_refused
    a, b = pair
    listener = a.listen(7, backlog: 1)
    b.connect("10.9.0.1", 7)
    assert_raises(Errno::ECONNREFUSED) { b.connect("10.9.0.1", 7) }
    assert listener.accept(timeout: 5)
    b.connect("10.9.0.1", 7)
    assert listener.accept(timeout: 5)
  end

  # A limit on descriptors holds for a whole process, so the accept runs
  # in a process of its own.
  def test_an_accept_with_no_descriptor_to_spare
    script = <<~'RUBY'
      require "sallyport"
      keys = Array.new(2) { Sallyport.private_key }
      a = Sallyport::Tunnel.new(private_key: keys[0], addresses: ["10.9.0.1"],
        peers: [{public_key: Sallyport.public_key(keys[1]), allowed_ips: ["10.9.0.2/32"]}])
      b = Sallyport::Tunnel.new(private_key: keys[1], addresses: ["10.9.0.2"],
        peers: [{public_key: Sallyport.public_key(keys[0]), endpoint: "127.0.0.1:#{a.listen_port}",
                 allowed_ips: ["10.9.0.1/32"]}])
      listener = a.listen(7)
      b.connect("10.9.0.1", 7)
      IO.select([listener], nil, nil, 5)
      Process.setrlimit(:NOFILE, Dir.children("/proc/self/fd").map(&:to_i).max + 1)
      held = []
      begin
        loop { held << File.open(File::NULL) }
      rescue Errno::EMFILE
        # Every descriptor that the limit allows is now in use.
      end
      begin
        listener.accept(timeout: 5)
        puts "accepted"
      rescue SystemCallError => e
        puts e.class
      end
    RUBY
    lib = File.expand_path("../lib", __dir__)
    assert_equal "Errno::EMFILE\n", IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)
  end

  def test_closing_a_listener_or_its_tunnel_ends_an_accept
    a, = pair
    [:first, :second].each do |round|
      listener = a.listen(7)
      waiting = Thread.new { listener.accept }
      waiting.report_on_exception = false
      sleep 0.01 until waiting.status == "sleep"
      (round == :first) ? listener.close : a.close
      assert_raises(IOError) { waiting.value }
    end
  end

  # Nothing carries bytes yet, so all that a connection can do is end.
  def test_a_connection_ends_when_either_side_closes_it
    a, b = pair
    listener = a.listen(7)
    [0, 1].each do |closer|
      ends = [b.connect("10.9.0.1", 7), listener.accept(timeout: 5)]
      ends[closer].close
      assert ends[1 - closer].wait_readable(5)
      assert_nil ends[1 - closer].read(1)
    end
  end
end

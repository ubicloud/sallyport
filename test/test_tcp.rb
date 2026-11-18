# frozen_string_literal: true

require_relative "helper"
require "digest"
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

  # The SYN of a connection over the backlog is dropped. It is sent again
  # a second later, and by then there is room.
  def test_a_connection_over_the_backlog_waits
    a, b = pair
    listener = a.listen(7, backlog: 1)
    b.connect("10.9.0.1", 7)
    waiting = Thread.new { b.connect("10.9.0.1", 7) }
    refute waiting.join(0.3)
    assert listener.accept(timeout: 5)
    assert waiting.value
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

  def test_bytes_cross_each_way
    a, b = pair
    ["10.9.0.1", "fd09::1"].each do |to|
      client, server = connection(a, b, to: to)
      client.write("ping")
      assert_equal "ping", server.readpartial(16)
      server.write("pong")
      assert_equal "pong", client.readpartial(16)
    end
  end

  def test_a_tunnel_counts_its_connections
    a, b = pair
    assert_equal [0, 0], [a, b].map(&:connections)
    ends = connection(a, b)
    eventually { [a, b].map(&:connections) == [1, 1] }
    ends.each(&:close)
    eventually { [a, b].map(&:connections) == [0, 0] }
    # An attempt counts while it lasts. Nothing listens here for the SYN
    # to find, and the peer's answer ends the attempt.
    assert_raises(Errno::ECONNREFUSED) { b.connect("10.9.0.1", 8) }
    eventually { b.connections.zero? }
  end

  def test_a_tunnel_describes_itself
    a, b = pair
    connection(a, b)
    text = a.dump
    assert_match(/^\d+ datagrams in: 0 from no peer, 0 refused, 0 from a source not allowed$/, text)
    assert_match(/^#{Regexp.escape(a.peers.first.public_key)} 127\.0\.0\.1:#{b.listen_port} \d+ \d+ \d+$/, text)
    assert_match(/^open 10\.9\.0\.1:7 to 10\.9\.0\.2:\d+: ESTABLISHED, 0 bytes to send and 0 to give Ruby, /, text)
    assert_match(/^  Socket \{ state: Established, /, text)
    assert_equal Encoding::UTF_8, text.encoding
  end

  def test_a_trace_of_the_packets_inside_a_tunnel
    a, b = pair(debug: "trace=100")
    client, server = connection(a, b)
    client.write("ping")
    assert_equal "ping", server.readpartial(16)
    trace = b.dump[/^the last TCP packets.*\n((?: .*\n)+)/, 1].lines
    assert_match(/\A +\d+\.\d{4} out \d+>7 S seq \d+ ack 0 win \d+ len 0\n\z/, trace[0])
    assert_match(/\A +\d+\.\d{4} in  7>\d+ S\. seq \d+ ack \d+ win \d+ len 0\n\z/, trace[1])
    assert(trace.any? { |line| line.match?(/ out \d+>7 P?\. seq \d+ ack \d+ win \d+ len 4\n\z/) })
    refute_match(/the last TCP packets/, pair.first.dump)
  end

  def test_each_direction_ends_on_its_own
    client, server = connection(*pair)
    client.write("question")
    client.close_write
    assert_equal "question", server.read
    server.write("answer")
    server.close
    assert_equal "answer", client.read
  end

  # The writer has more to send than the buffers along the way hold, so
  # it must wait for the reader, and the reader must get every byte.
  def test_a_reader_that_stops_holds_the_writer_and_loses_nothing
    data = Random.new(1).bytes(8 << 20)
    connection(*pair).permutation do |from, to|
      writer = Thread.new do
        from.write(data)
        :written
      end
      sleep 0.2
      assert writer.alive?
      got = +""
      got << to.readpartial(1 << 20) while got.bytesize < data.bytesize
      assert_equal Digest::SHA256.hexdigest(data), Digest::SHA256.hexdigest(got)
      assert_equal :written, writer.value
    end
  end

  def test_many_connections_at_once
    a, b = pair
    listener = a.listen(7, backlog: 32)
    servers = Thread.new do
      Array.new(24) do
        Thread.new(listener.accept(timeout: 10)) do |server|
          server.write(server.read.upcase)
          server.close
        end
      end.each(&:join)
    end
    clients = Array.new(24) do |i|
      Thread.new do
        client = b.connect("10.9.0.1", 7)
        client.write("stream #{i} " * 2000)
        client.close_write
        client.read.tap { client.close }
      end
    end
    clients.each_with_index { |client, i| assert_equal "STREAM #{i} " * 2000, client.value }
    servers.join
  end

  # A Unix socket has no way to tell of a reset, so the end of the stream
  # has to.
  def test_closing_with_bytes_unread_resets_the_connection
    client, server = connection(*pair)
    server.write("unread")
    assert client.wait_readable(5)
    client.close
    assert_nil server.read(1)
    # The tunnel's thread ends the stream and then closes its end. A
    # write may fall between the two, and the next one then finds that
    # what it wrote was never read.
    assert_raises(Errno::EPIPE, Errno::ECONNRESET) { loop { server.write("more") } }
  end

  def test_closing_a_tunnel_sends_what_was_written
    data = Random.new(2).bytes(1 << 20)
    [true, false].each do |closed|
      b, a = pair.reverse
      client, server = connection(a, b)
      reader = Thread.new { server.read }
      client.write(data)
      client.close if closed
      b.close
      assert_equal Digest::SHA256.hexdigest(data), Digest::SHA256.hexdigest(reader.value)
    end
  end

  def test_closing_a_tunnel_tells_its_peers
    [1, 0].each do |linger|
      a, b = pair
      client, server = connection(a, b)
      a.close(linger: linger)
      assert_nil server.read(1)
      assert client.wait_readable(5)
      assert_nil client.read(1)
    end
  end

  # A linger that is no number is refused before the tunnel is touched.
  def test_a_linger_that_is_no_number_leaves_the_tunnel_open
    a, = pair
    [nil, "soon", Float::NAN].each do |linger|
      assert_raises(TypeError, ArgumentError) { a.close(linger: linger) }
      refute_predicate a, :closed?
    end
    a.close(linger: Float::INFINITY)
    assert_predicate a, :closed?
  end
end

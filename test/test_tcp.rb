# frozen_string_literal: true

require_relative "helper"

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
end

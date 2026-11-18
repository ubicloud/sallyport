# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sallyport"
require "minitest/autorun"
require "socket"

module Helper
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

  # Returns a UDP port that was free a moment ago.
  def free_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    socket.addr[1]
  ensure
    socket&.close
  end
end

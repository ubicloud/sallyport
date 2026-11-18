# frozen_string_literal: true

require "io/wait"

module Sallyport
  # A Peer is what a tunnel knows of one of its peers: the peer's public
  # key, the address and port that it was last heard from or was
  # configured with, the seconds since its last handshake, and the bytes
  # of the packets sent to it and received from it. The endpoint and the
  # age are nil where there is none.
  Peer = Struct.new(:public_key, :endpoint, :handshake_age, :tx_bytes, :rx_bytes) do
    # Says whether the peer completed a handshake in the last +within+
    # seconds. WireGuard uses a session for three minutes at most. A
    # handshake older than that means that no session is left, because
    # the peer cannot be reached or because nothing was sent to it.
    def alive?(within: 180)
      !handshake_age.nil? && handshake_age <= within
    end
  end

  # A WireGuard interface inside this process. A thread of its own serves
  # it, and that thread never takes the GVL. There is no TUN device, no
  # routing table and no privilege: all that the system sees of a tunnel
  # is a UDP socket.
  #
  # A tunnel does not survive fork. Make it in the process that uses it.
  # If a child is forked while a tunnel is open, it has copies of the
  # tunnel's descriptors, and the UDP port stays bound until the child
  # ends or calls exec.
  class Tunnel
    # A tunnel that is closed, or let go of, gives its connections this
    # many seconds to end in order.
    LINGER = 1

    # The tunnel's UDP port, which the system chose if the configuration
    # named none.
    attr_reader :listen_port

    # Starts a tunnel from a configuration in the format of wg-quick(8), or
    # from the parts that Tunnel.config takes. An endpoint that is a host
    # name is resolved now, and not again. Nothing can interrupt the call
    # while it resolves a name.
    #
    # +debug+ is for looking inside a tunnel: settings with commas between
    # them, which the environment gives as SALLYPORT_DEBUG if the caller
    # gives none. "trace=N" keeps a line for each of the last N TCP
    # packets, and Tunnel#dump then returns them.
    #
    # Raises ArgumentError for a fault in the configuration, and the
    # system's error, such as Errno::EADDRINUSE, if the tunnel cannot be
    # started.
    def initialize(config = nil, debug: ENV["SALLYPORT_DEBUG"], **parts)
      @lock = Mutex.new
      raise ArgumentError, "a tunnel takes a configuration or its parts, and not both" if config && !parts.empty?

      config ||= self.class.config(**parts)
      # The library takes C strings, and one would end at a NUL.
      [config, debug || ""].each do |text|
        raise TypeError, "the configuration is not a String" unless text.is_a?(String)
        raise ArgumentError, "the configuration holds a NUL" if text.include?("\0")
      end

      reason = Fiddle::Pointer.malloc(256, Fiddle::RUBY_FREE)
      @pid = Process.pid
      # An exception that another thread raises waits until the handle has
      # an owner. One that came between the call and the assignment would
      # leave a tunnel running that nothing could close. Ruby does not make
      # the exception of a signal wait, so Ctrl-C at that moment still does
      # that.
      code = Thread.handle_interrupt(Object => :never) do
        handle = Native::OPEN.call(config, debug, reason, 256)
        next Fiddle.last_error if handle.null?

        # Tunnel#close and the finalizer each take the handle out of this
        # holder, so whichever comes first is the only one to free it.
        @holder = [handle]
        ObjectSpace.define_finalizer(self, self.class.finalizer(@holder, @pid))
        @listen_port = Native::PORT.call(handle)
        nil
      end
      return unless code

      reason = reason.to_s.force_encoding(Encoding::UTF_8)
      raise ArgumentError, reason if code == Errno::EINVAL::Errno

      raise SystemCallError.new(reason, code)
    end

    # A copy would share the handle, which has one owner. dup and clone
    # have given the copy the finalizer by now, and it would close the
    # tunnel when the copy was collected.
    def initialize_copy(*)
      ObjectSpace.undefine_finalizer(self)
      @holder = []
      raise TypeError, "a tunnel cannot be copied"
    end

    # Connects to a TCP port of an IP address through the tunnel, and
    # returns the connection's Socket.
    #
    # Raises as connect(2) would: Errno::ECONNREFUSED, Errno::ENETUNREACH
    # if no peer's AllowedIPs hold the address, and Errno::ETIMEDOUT if the
    # connection is not established in +timeout+ seconds. Raises
    # SocketError if +host+ is not an IP address, and Errno::ENETDOWN if
    # the tunnel has failed.
    def connect(host, port, timeout: 30)
      port = self.class.port(port)
      # An address is asked for, and never a name: a tunnel has no
      # resolver.
      remote = Addrinfo.getaddrinfo(host.to_s, port, nil, :STREAM, nil, ::Socket::AI_NUMERICHOST).first
      # ::ffff:10.9.0.1 is the IPv4 address 10.9.0.1 in IPv6's writing.
      remote = Addrinfo.tcp(remote.ipv6_to_ipv4.ip_address, port) if remote.ipv6_v4mapped?
      to = "#{remote.ip_address} port #{port}"
      # The wait for the lock can be interrupted. From the call until the
      # descriptor has an owner, an exception from another thread waits.
      socket = synchronize do
        Thread.handle_interrupt(Object => :never) do
          fd, code = Native::CONNECT.call(handle, remote.ip_address, port), Fiddle.last_error
          raise SystemCallError.new(to, code) if fd.negative?

          Socket.adopt(fd, remote, self)
        end
      end
      begin
        raise Errno::ETIMEDOUT, to unless socket.wait_readable(timeout)

        outcome(socket, to)
        established = socket
      ensure
        socket.close unless established
      end
    end

    # Listens on a TCP port of the tunnel's addresses, and returns the
    # Listener. At most +backlog+ connections, and no more than 128, wait
    # to be accepted. One that would be one more gets no answer, and its
    # peer tries again.
    #
    # Raises Errno::EADDRINUSE if the tunnel listens on the port already.
    def listen(port, backlog: 32)
      port = self.class.port(port)
      backlog = Integer(backlog)
      # The wait for the lock can be interrupted. From the call until the
      # descriptor has an owner, an exception from another thread waits.
      io = synchronize do
        Thread.handle_interrupt(Object => :never) do
          fd, code = Native::LISTEN.call(handle, port, backlog), Fiddle.last_error
          raise SystemCallError.new("TCP port #{port}", code) if fd.negative?

          UNIXSocket.for_fd(fd)
        end
      end
      begin
        outcome(io, "TCP port #{port}")
        listener = Listener.new(io, port, self)
      ensure
        io.close unless listener
      end
    end

    # Stops the tunnel. Its listeners stop at once. Each connection is
    # ended as if its Socket had been closed: what was written to it is
    # sent, and then the end of its stream. The call waits for that for up
    # to +linger+ seconds, and resets a connection that has not ended by
    # then. Every socket and listener of the tunnel then reaches end of
    # file. If another thread writes to a socket while the tunnel closes,
    # those bytes are not sent. A signal handler cannot call this, because
    # it takes a lock.
    def close(linger: LINGER)
      # The linger is made a number before the handle is taken. One that
      # is no number then leaves the tunnel as it was.
      milliseconds = self.class.milliseconds(linger)
      synchronize { self.class.release(@holder, @pid, milliseconds) }
      nil
    end

    def closed?
      @holder.empty?
    end

    # Returns how many connections the tunnel has: those that it is
    # making, and those that are made and have not ended. A connection
    # that a peer makes to a listener counts once its handshake is done.
    # One that was closed on this side counts until the peer has all that
    # was written to it and has ended its own stream too, or until it is
    # reset.
    def connections
      synchronize { Native::CONNECTIONS.call(handle) }
    end

    # Returns a description of the tunnel for a person to read: what it
    # has counted, a line for each peer, and two lines for each connection,
    # of which the second is the TCP socket as smoltcp prints it. It is
    # there to show why something does not move, and its form may change.
    def dump
      size = 1 << 16
      loop do
        text = Fiddle::Pointer.malloc(size, Fiddle::RUBY_FREE)
        need = synchronize { Native::DUMP.call(handle, text, size) }
        raise Errno::ENETDOWN, "the tunnel's thread does not answer" if need.zero?
        return text.to_s.force_encoding(Encoding::UTF_8) if need <= size

        size = need
      end
    end

    # Returns a Peer for each peer, in the order of the configuration.
    # What it says is a quarter of a second old at most.
    def peers
      stats.lines.map do |line|
        key, endpoint, age, tx, rx = line.split
        Peer.new(key, (endpoint unless endpoint == "-"), (age.to_i / 1000.0 unless age == "-1"), tx.to_i, rx.to_i)
      end
    end

    # Returns the configuration, in the format of wg-quick(8), of a tunnel
    # with these parts. Each peer is a Hash with :public_key, and
    # optionally :allowed_ips, :endpoint, :preshared_key and
    # :persistent_keepalive.
    def self.config(private_key:, addresses:, listen_port: nil, mtu: nil, peers: [])
      list = ->(name, values) { values.empty? ? [] : ["#{name} = #{values.map { |v| network(v) }.join(", ")}"] }
      lines = ["[Interface]", "PrivateKey = #{private_key}", *list.("Address", Array(addresses))]
      lines << "ListenPort = #{listen_port}" if listen_port
      lines << "MTU = #{mtu}" if mtu
      peers.each do |peer|
        lines << "[Peer]" << "PublicKey = #{peer.fetch(:public_key)}"
        lines << "PresharedKey = #{peer[:preshared_key]}" if peer[:preshared_key]
        lines << "Endpoint = #{peer[:endpoint]}" if peer[:endpoint]
        lines.concat(list.("AllowedIPs", Array(peer[:allowed_ips])))
        lines << "PersistentKeepalive = #{peer[:persistent_keepalive]}" if peer[:persistent_keepalive]
      end
      # A value with a line break in it would add a line of its own, and
      # what follows a "#" would be taken for a comment.
      raise ArgumentError, "a configuration value holds a line break or a #" if lines.any? { |l| l.match?(/[\r\n#]/) }

      lines.join("\n")
    end

    # Returns a TCP port as an Integer. A String is read as decimal, where
    # Integer would read "022" as octal.
    def self.port(port) # :nodoc:
      port = Integer(port, 10) if port.is_a?(String)
      raise ArgumentError, "#{port.inspect} is not a TCP port" unless port.is_a?(Integer) && port.between?(1, 65_535)

      port
    end

    # Writes one address or network. An IPAddr keeps its prefix apart from
    # the rest of what it prints, and a comma would make two of one.
    def self.network(value) # :nodoc:
      text = value.respond_to?(:prefix) ? "#{value}/#{value.prefix}" : value.to_s
      raise ArgumentError, "#{text.inspect} is not one address or network" if text.include?(",")

      text
    end

    # Returns a linger in milliseconds, and no more of them than the
    # library takes.
    def self.milliseconds(seconds) # :nodoc:
      seconds = Float(seconds)
      raise ArgumentError, "a linger is a number of seconds" if seconds.nan?

      (seconds.clamp(0, 2_000_000) * 1000).round
    end

    # Frees the handle that a holder has, if it still has one. A forked
    # child has the handle and not the thread, and frees nothing.
    def self.release(holder, pid, milliseconds = LINGER * 1000) # :nodoc:
      # An exception from another thread between the two lines would leave
      # the tunnel running with nothing to close it. Nothing between them
      # raises one of its own.
      Thread.handle_interrupt(Object => :never) do
        handle = holder.pop
        Native::CLOSE.call(handle, milliseconds) if handle && pid == Process.pid
      end
    end

    def self.finalizer(holder, pid) # :nodoc:
      proc { release(holder, pid) }
    end

    private

    # Runs the block with the tunnel's lock held. The lock is a Mutex and
    # not a Monitor. A Monitor lets in the thread that holds it, and so it
    # would let a signal handler close the tunnel under a call of that
    # thread.
    def synchronize(&)
      @lock.synchronize(&)
    end

    # Returns the handle for a call into the library. The caller holds the
    # lock, so that the tunnel is not closed while the call runs.
    def handle
      handle = @holder.first or raise IOError, "the tunnel is closed"
      raise Error, "a tunnel does not survive fork" unless @pid == Process.pid

      handle
    end

    # Reads the status that the tunnel's thread sends first on a pair, and
    # raises what it stands for unless it is 0.
    def outcome(io, what)
      # recv takes the status and no more. A buffered read would take
      # with it whatever else has arrived, and what does not read through
      # Ruby's buffer, as OpenSSL does not, would miss that.
      status = io.recv(1)
      # The thread closes its end when the tunnel is closed. At the end of
      # a stream recv returns nil, or "" before Ruby 3.3.
      raise IOError, "the tunnel was closed" if status.nil? || status.empty?
      raise Native::STATUS.fetch(status.ord), what unless status.ord.zero?
    end

    def stats
      size = 4096
      loop do
        text = Fiddle::Pointer.malloc(size, Fiddle::RUBY_FREE)
        need = synchronize { Native::STATS.call(handle, text, size) }
        return text.to_s.force_encoding(Encoding::UTF_8) if need <= size

        size = need * 2
      end
    end
  end
end

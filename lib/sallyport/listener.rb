# frozen_string_literal: true

require "io/wait"
require "socket"

module Sallyport
  # A Listener is a TCP port of a tunnel's addresses that is listened on.
  # Closing it stops the listening, and the connections that it has
  # accepted stay open.
  class Listener
    attr_reader :port

    # The tunnel that the listener listens through. A listener keeps its
    # tunnel from the garbage collector, as a Socket does.
    attr_reader :tunnel

    def initialize(io, port, tunnel) # :nodoc:
      @io = io
      @port = port
      @tunnel = tunnel
    end

    # Waits for a connection and returns its Socket, or returns nil if
    # +timeout+ seconds pass first. Raises IOError once the listener or
    # its tunnel is closed.
    def accept(timeout: nil)
      deadline = timeout && (now + timeout)
      loop do
        # An interrupt waits until a connection that was taken has an
        # owner.
        socket = Thread.handle_interrupt(Object => :never) { take }
        return socket if socket
        return nil unless @io.wait_readable(deadline && [deadline - now, 0].max)
      end
    end

    # Returns the IO to wait on, as in IO.select, for a connection to
    # accept.
    def to_io
      @io
    end

    def close
      @io.close unless @io.closed?
    end

    def closed?
      @io.closed?
    end

    private

    # TLA-listen@60> \* Listener#take: Ruby takes a connection, and answers.
    # TLA-listen@60> Accept == s.open /\ s.queued > 0 /\ s' = [s EXCEPT !.queued = @ - 1, !.answers = @ + 1]

    # Takes a connection that has arrived, and returns its Socket, or nil
    # if none has. The tunnel's thread sends each as a message that names
    # the peer and carries the connection's descriptor.
    def take
      from, _, flags, rights = @io.recvmsg_nonblock(64, 0, 64, scm_rights: true, exception: false)
      return nil if from == :wait_readable
      raise IOError, "the tunnel was closed" if from.nil? || from.empty?

      answer
      # The system gives no descriptor to a process that has its limit of
      # them, and the connection is lost.
      raise Errno::EMFILE, "a connection from #{from}" unless (flags & ::Socket::MSG_CTRUNC).zero?

      io = rights&.unix_rights&.first
      peer = /\A(\S+) (\d+)\z/.match(from)
      raise IOError, "a connection arrived without its descriptor or its peer" unless io && peer

      io.autoclose = false
      Socket.adopt(io.fileno, Addrinfo.tcp(peer[1], peer[2].to_i), @tunnel)
    end

    # Tells the tunnel's thread that a connection was accepted, which
    # makes room in the backlog for another.
    def answer
      @io.send("\0", 0)
    rescue Errno::EPIPE, Errno::ECONNRESET
      # The tunnel was closed a moment ago, and the connection with it.
    end

    def now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end

# frozen_string_literal: true

module Sallyport
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
    # Starts a tunnel from a configuration in the format of wg-quick(8), or
    # from the parts that Tunnel.config takes. An endpoint that is a host
    # name is resolved now, and not again. Nothing can interrupt the call
    # while it resolves a name.
    #
    # Raises ArgumentError for a fault in the configuration, and the
    # system's error, such as Errno::EADDRINUSE, if the tunnel cannot be
    # started.
    def initialize(config = nil, **parts)
      @lock = Mutex.new
      raise ArgumentError, "a tunnel takes a configuration or its parts, and not both" if config && !parts.empty?

      config ||= self.class.config(**parts)
      raise TypeError, "the configuration is not a String" unless config.is_a?(String)
      # The library takes a C string, which would end at the NUL.
      raise ArgumentError, "the configuration holds a NUL" if config.include?("\0")

      reason = Fiddle::Pointer.malloc(256, Fiddle::RUBY_FREE)
      @pid = Process.pid
      # An exception that another thread raises waits until the handle has
      # an owner. One that came between the call and the assignment would
      # leave a tunnel running that nothing could close. Ruby does not make
      # the exception of a signal wait, so Ctrl-C at that moment still does
      # that.
      code = Thread.handle_interrupt(Object => :never) do
        handle = Native::OPEN.call(config, reason, 256)
        next Fiddle.last_error if handle.null?

        # Tunnel#close and the finalizer each take the handle out of this
        # holder, so whichever comes first is the only one to free it.
        @holder = [handle]
        ObjectSpace.define_finalizer(self, self.class.finalizer(@holder, @pid))
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

    # Stops the tunnel. A signal handler cannot call this, because it
    # takes a lock.
    def close
      synchronize { self.class.release(@holder, @pid) }
      nil
    end

    def closed?
      @holder.empty?
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

    # Writes one address or network. An IPAddr keeps its prefix apart from
    # the rest of what it prints, and a comma would make two of one.
    def self.network(value) # :nodoc:
      text = value.respond_to?(:prefix) ? "#{value}/#{value.prefix}" : value.to_s
      raise ArgumentError, "#{text.inspect} is not one address or network" if text.include?(",")

      text
    end

    # Frees the handle that a holder has, if it still has one. A forked
    # child has the handle and not the thread, and frees nothing.
    def self.release(holder, pid) # :nodoc:
      # An exception from another thread between the two lines would leave
      # the tunnel running with nothing to close it.
      Thread.handle_interrupt(Object => :never) do
        handle = holder.pop
        Native::CLOSE.call(handle) if handle && pid == Process.pid
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
  end
end

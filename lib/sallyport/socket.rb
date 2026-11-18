# frozen_string_literal: true

require "socket"

module Sallyport
  # A Socket is a TCP connection through a tunnel. To the operating system
  # it is one end of a Unix socket pair, so it has a descriptor of its own:
  # it can be selected on, and OpenSSL can run TLS on it. Where the pair
  # and the TCP connection differ, as in who the peer is, it answers for
  # the TCP connection.
  class Socket < ::UNIXSocket
    # The far end of the TCP connection, as an Addrinfo.
    attr_reader :remote_address

    # The tunnel that the connection goes through. A socket keeps its
    # tunnel from the garbage collector, which would close it.
    attr_reader :tunnel

    # Returns the far end as a TCPSocket would: its family, its port and
    # its address. OpenSSL passes this on for the socket that it wraps.
    def peeraddr(*)
      family = remote_address.ipv6? ? "AF_INET6" : "AF_INET"
      [family, remote_address.ip_port, remote_address.ip_address, remote_address.ip_address]
    end

    # Returns the far end as a packed sockaddr, which Net::SSH asks for.
    def getpeername
      remote_address.to_sockaddr
    end

    # Takes an option of TCP and does nothing, because there is nothing
    # for one to act on: the tunnel's stack sends without delay as it is.
    # Net::SSH sets TCP_NODELAY on every socket that it is given. Any
    # other option goes to the pair.
    def setsockopt(*args)
      level = args.first
      level = level.level if level.is_a?(::Socket::Option)
      return 0 if [::Socket::IPPROTO_TCP, :TCP, :IPPROTO_TCP, "TCP", "IPPROTO_TCP"].include?(level)

      super
    end

    # A descriptor sent on the pair would arrive in the peer's stream as a
    # byte of nothing.
    undef_method :send_io, :recv_io

    def inspect
      "#<#{self.class} #{remote_address.inspect_sockaddr} fd=#{closed? ? "closed" : fileno}>"
    end

    def self.adopt(fd, remote, tunnel) # :nodoc:
      socket = for_fd(fd)
      socket.instance_variable_set(:@remote_address, remote)
      socket.instance_variable_set(:@tunnel, tunnel)
      socket
    end

    # A Socket comes from Tunnel#connect or Listener#accept, and from
    # nowhere else.
    private_class_method :new, :open, :pair, :socketpair, :for_fd
  end
end

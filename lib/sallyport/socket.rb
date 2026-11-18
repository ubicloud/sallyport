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

    def inspect
      "#<#{self.class} #{remote_address.inspect_sockaddr} fd=#{closed? ? "closed" : fileno}>"
    end

    def self.adopt(fd, remote, tunnel) # :nodoc:
      socket = for_fd(fd)
      socket.instance_variable_set(:@remote_address, remote)
      socket.instance_variable_set(:@tunnel, tunnel)
      socket
    end
  end
end

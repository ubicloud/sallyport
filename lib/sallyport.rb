# frozen_string_literal: true

require_relative "sallyport/version"
require_relative "sallyport/native"
require_relative "sallyport/tunnel"

# WireGuard and TCP in user space: connections through a WireGuard tunnel,
# as sockets with real descriptors, without a TUN device.
module Sallyport
  class Error < StandardError; end

  # Returns a new private key, in base64.
  def self.private_key
    out = Fiddle::Pointer.malloc(45, Fiddle::RUBY_FREE)
    raise Error, "the system gave no random bytes for a key" unless Native::PRIVATE_KEY.call(out).zero?

    out.to_s.force_encoding(Encoding::UTF_8)
  end

  # Returns the public key of a private key, both in base64.
  def self.public_key(private_key)
    out = Fiddle::Pointer.malloc(45, Fiddle::RUBY_FREE)
    raise ArgumentError, "a key must be 32 bytes in base64" unless Native::PUBLIC_KEY.call(private_key.to_s, out).zero?

    out.to_s.force_encoding(Encoding::UTF_8)
  end
end

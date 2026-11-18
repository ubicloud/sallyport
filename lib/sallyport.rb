# frozen_string_literal: true

require_relative "sallyport/version"
require_relative "sallyport/native"

# WireGuard and TCP in user space: connections through a WireGuard tunnel,
# as sockets with real descriptors, without a TUN device.
module Sallyport
  class Error < StandardError; end
end

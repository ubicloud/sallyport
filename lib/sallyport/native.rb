# frozen_string_literal: true

require "fiddle"

module Sallyport
  # The C ABI of the Rust library, bound by hand.
  module Native
    NAME = "libsallyport.so"

    # The library is beside this file in an installed gem, or else where
    # RubyGems keeps a gem's extensions, which is on the load path. In a
    # checkout it is where cargo built it.
    def self.path
      built = File.expand_path("../../ext/sallyport/target/release", __dir__)
      dirs = [__dir__, *$LOAD_PATH.map { |d| File.join(d.to_s, "sallyport") }, built]
      dirs.map { |d| File.join(d, NAME) }.find { |p| File.exist?(p) } or
        raise LoadError, "#{NAME} is not built: run `rake compile`"
    end

    LIB = Fiddle.dlopen(path)
    P = Fiddle::TYPE_VOIDP
    I = Fiddle::TYPE_INT
    Z = Fiddle::TYPE_SIZE_T

    # Binds a function of the library. Ruby keeps the GVL for a call
    # unless the function +waits+. A thread that lets the GVL go has to
    # get it back, which takes as long as another thread cares to compute,
    # and no function that does not wait is worth that.
    def self.bind(name, args, ret, waits: false)
      Fiddle::Function.new(LIB[name], args, ret, need_gvl: !waits)
    end

    VERSION = bind("sp_version", [], P)
    OPEN = bind("sp_open", [P, P, P, Z], P, waits: true)
    CLOSE = bind("sp_close", [P, I], Fiddle::TYPE_VOID, waits: true)
    CONNECT = bind("sp_connect", [P, P, I], I)
    LISTEN = bind("sp_listen", [P, I, I], I)
    CONNECTIONS = bind("sp_connections", [P], Z)
    DUMP = bind("sp_dump", [P, P, Z], Z, waits: true)
    PORT = bind("sp_port", [P], I)
    STATS = bind("sp_stats", [P, P, Z], Z)
    PRIVATE_KEY = bind("sp_private_key", [P], I)
    PUBLIC_KEY = bind("sp_public_key", [P, P], I)

    # The tunnel's thread first sends a status on the pair of a connection
    # or of a listener. It is 0 if the connection is established or the
    # port is listened on, and otherwise it is one of these.
    STATUS = {
      1 => Errno::ECONNREFUSED,
      2 => Errno::ETIMEDOUT,
      3 => Errno::ENETUNREACH,
      4 => Errno::EADDRNOTAVAIL,
      5 => Errno::EADDRINUSE
    }.freeze

    unless VERSION.call.to_s == Sallyport::VERSION
      raise LoadError, "#{NAME} is version #{VERSION.call}, and the gem is #{Sallyport::VERSION}: run `rake compile`"
    end
  end
end

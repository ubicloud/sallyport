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

    # Binds a function of the library. Ruby keeps the GVL for a call
    # unless the function +waits+. A thread that lets the GVL go has to
    # get it back, which takes as long as another thread cares to compute,
    # and no function that does not wait is worth that.
    def self.bind(name, args, ret, waits: false)
      Fiddle::Function.new(LIB[name], args, ret, need_gvl: !waits)
    end

    VERSION = bind("sp_version", [], P)
    PRIVATE_KEY = bind("sp_private_key", [P], I)
    PUBLIC_KEY = bind("sp_public_key", [P, P], I)

    unless VERSION.call.to_s == Sallyport::VERSION
      raise LoadError, "#{NAME} is version #{VERSION.call}, and the gem is #{Sallyport::VERSION}: run `rake compile`"
    end
  end
end

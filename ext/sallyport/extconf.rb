# frozen_string_literal: true

# RubyGems runs this when the gem is installed. There is no Ruby extension
# to compile: the library is Rust with a C ABI, which
# lib/sallyport/native.rb binds with Fiddle. So the Makefile written here
# has cargo build the library, and puts it beside native.rb.

require "rbconfig"
require "shellwords"

unless system("cargo", "--version", out: File::NULL)
  abort "sallyport needs cargo to build its Rust library: see https://rustup.rs"
end

# A path is quoted for the shell, and its dollars for make.
quoted = ->(path) { Shellwords.escape(path).gsub("$", "$$") }

File.write("Makefile", <<~MAKE)
  sitearchdir = #{quoted.(RbConfig::CONFIG["sitearchdir"])}
  target = #{quoted.(File.join(Dir.pwd, "target"))}

  # A target triple in the environment would move what cargo builds.
  all:
  \tenv -u CARGO_BUILD_TARGET cargo build --release --locked --manifest-path #{quoted.(File.join(__dir__, "Cargo.toml"))} --target-dir $(target)

  install: all
  \tmkdir -p $(DESTDIR)$(sitearchdir)/sallyport
  \tcp $(target)/release/libsallyport.so $(DESTDIR)$(sitearchdir)/sallyport/

  clean:
  \trm -rf $(target)

  .PHONY: all install clean
MAKE

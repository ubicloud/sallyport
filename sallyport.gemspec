# frozen_string_literal: true

require_relative "lib/sallyport/version"

Gem::Specification.new do |s|
  s.name = "sallyport"
  s.version = Sallyport::VERSION
  s.summary = "WireGuard and TCP in user space, as sockets with real descriptors"
  s.description = <<~TEXT
    Connections through a WireGuard tunnel without a TUN device, a routing
    table or privilege: boringtun and smoltcp on a thread that never takes
    the GVL. Each connection is a socket with a descriptor, so OpenSSL and
    Net::SSH can use it as they would any other.
  TEXT
  s.authors = ["Ubicloud"]
  s.homepage = "https://github.com/ubicloud/sallyport"
  # The library is built with the copies of boringtun and smoltcp in
  # ext/sallyport/vendor. Each copy is under the license of its project.
  s.licenses = ["Apache-2.0", "0BSD", "BSD-3-Clause"]
  s.required_ruby_version = ">= 3.1"

  s.files = Dir.chdir(__dir__) do
    # The copies go in whole, with their licenses. Some of their files
    # have names that begin with a dot.
    vendored = Dir.glob("ext/sallyport/vendor/**/*", File::FNM_DOTMATCH).select { |path| File.file?(path) }
    Dir["lib/**/*.rb", "ext/sallyport/{Cargo.toml,Cargo.lock,extconf.rb}", "ext/sallyport/src/*.rs", "LICENSE", "README.md"] +
      vendored.reject { |path| path.include?("/target/") }
  end
  s.extensions = ["ext/sallyport/extconf.rb"]

  # Fiddle is a default gem until Ruby 3.5, and a bundled one after.
  s.add_dependency "fiddle", "~> 1.1"
end

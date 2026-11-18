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
  s.license = "Apache-2.0"
  s.required_ruby_version = ">= 3.1"

  s.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "ext/sallyport/{Cargo.toml,Cargo.lock,extconf.rb}", "ext/sallyport/src/*.rs", "LICENSE"]
  end
  s.extensions = ["ext/sallyport/extconf.rb"]

  # Fiddle is a default gem until Ruby 3.5, and a bundled one after.
  s.add_dependency "fiddle", "~> 1.1"
end

# frozen_string_literal: true

require "rake/testtask"

desc "Build the Rust library"
task :compile do
  sh "cargo", "build", "--release", "--locked", "--manifest-path", "ext/sallyport/Cargo.toml"
end

desc "Run the Rust library's unit tests"
task :unit do
  sh "cargo", "test", "--release", "--locked", "--manifest-path", "ext/sallyport/Cargo.toml"
end

desc "Run the unit tests that wait for a timer of WireGuard or of TCP to run out"
task :slow do
  sh "cargo", "test", "--release", "--locked", "--manifest-path", "ext/sallyport/Cargo.toml", "--", "--ignored"
end

# Wireproxy is the second implementation that the tests talk to. It is a
# Go program, and its go.mod asks for Go 1.26.
WIREPROXY = "github.com/windtf/wireproxy/cmd/wireproxy@v1.1.3"

desc "Build the programs that the tests run against into tmp/bin (needs Go)"
task :fixtures do
  bin = File.expand_path("tmp/bin", __dir__)
  mkdir_p bin
  sh({"GOBIN" => bin}, "go", "install", WIREPROXY)
  # An SSH server, for Net::SSH to reach through a tunnel.
  sh "go", "build", "-C", "test/support/sshd", "-o", File.join(bin, "sshd"), "."
  # A peer that has the Linux kernel for its TCP. Its tests take root.
  sh "go", "build", "-C", "test/support/kernelpeer", "-o", File.join(bin, "kernelpeer"), "."
end

Rake::TestTask.new(test: %i[compile unit]) do |t|
  t.libs << "lib"
  t.test_files = FileList["test/test_*.rb"]
  t.warning = true
end

task default: :test

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

# VPP is a heavier program to test against, and it is apart from the
# other fixtures. These are fd.io's packages for Ubuntu 24.04. They are
# unpacked into tmp/vpp/root and not installed. test/test_vpp.rb runs
# what is unpacked as root, so each file is held to its SHA-256.
FDIO = "https://packagecloud.io/fdio/release/ubuntu/pool/noble/main"
VPP = "26.10-release"
VPP_PACKAGES = {
  "amd64" => {
    "libvppinfra" => "0e56202cc43bb6829c9157e0fc119c3d643b480bbd380ad561f5d157ff3e39a5",
    "vpp" => "3332807ae036a9a69e37737ca7c1223234d8ff48ae94cf1928ec23094a1a5aca",
    "vpp-plugin-core" => "b6c29db269040ca01a40f69fc41db209a83eed29ae655fc94f877dcc333cc466",
    "vpp-crypto-engines" => "b4b7e66c096a4d1312f3b7ee0e5d558481463b294a927c8d7dd27ba972543165"
  },
  "arm64" => {
    "libvppinfra" => "828e2eb189663d15fe00794a7c64395a96c969535c6dd842648ac61864d701c0",
    "vpp" => "d56b0ff79ca8cfd863b122da6f19c3b1a9880326ec2db813bd7834d0dfabbad5",
    "vpp-plugin-core" => "b4100bb8080cd8ac0967af027cc46bbc63bb7dc2fca1acb6d4df2ce5cb1b8b47",
    "vpp-crypto-engines" => "0dd52f8b62283190e209e37c1212d51afd720e8e79b866402db0c620c0e057e4"
  }
}.freeze

desc "Fetch VPP into tmp/vpp/root (needs curl and dpkg)"
task :vpp do
  require "digest"
  arch = `dpkg --print-architecture`.strip
  packages = VPP_PACKAGES.fetch(arch) { abort "no package of VPP is listed for #{arch.inspect}" }
  version = "#{VPP} #{arch}\n"
  next if File.exist?("tmp/vpp/root/version") && File.read("tmp/vpp/root/version") == version

  # The tree is unpacked beside its place and then moved there, so that a
  # fetch that fails leaves no part of one behind.
  rm_rf "tmp/vpp/new"
  mkdir_p "tmp/vpp/new"
  packages.each do |name, sha256|
    # The repository files a package under the first letter of its name,
    # or under the first four where the name starts with "lib".
    shelf = name[0, name.start_with?("lib") ? 4 : 1]
    deb = "tmp/vpp/#{name}.deb"
    sh "curl", "-sSfL", "-o", deb, "#{FDIO}/#{shelf}/vpp/#{name}_#{VPP}_#{arch}.deb"
    abort "#{deb} is not the file that is expected" unless Digest::SHA256.file(deb).hexdigest == sha256
    sh "dpkg", "-x", deb, "tmp/vpp/new"
  end
  File.write("tmp/vpp/new/version", version)
  rm_rf "tmp/vpp/root"
  mv "tmp/vpp/new", "tmp/vpp/root"
end

Rake::TestTask.new(test: %i[compile unit]) do |t|
  t.libs << "lib"
  t.test_files = FileList["test/test_*.rb"]
  t.warning = true
end

task default: :test

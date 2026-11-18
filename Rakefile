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

desc "Run the unit tests that wait for a timer of WireGuard to run out"
task :slow do
  sh "cargo", "test", "--release", "--locked", "--manifest-path", "ext/sallyport/Cargo.toml", "--", "--ignored"
end

Rake::TestTask.new(test: %i[compile unit]) do |t|
  t.libs << "lib"
  t.test_files = FileList["test/test_*.rb"]
  t.warning = true
end

task default: :test

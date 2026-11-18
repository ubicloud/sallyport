# frozen_string_literal: true

require_relative "helper"

class TestSallyport < Minitest::Test
  def test_the_library_loads_and_is_the_gems_version
    assert_equal Sallyport::VERSION, Sallyport::Native::VERSION.call.to_s
  end

  def test_keys
    private_key = Sallyport.private_key
    public_key = Sallyport.public_key(private_key)
    assert_equal [32, 32], [private_key, public_key].map { |k| k.unpack1("m").bytesize }
    assert_equal [Encoding::UTF_8] * 2, [private_key, public_key].map(&:encoding)
    refute_equal private_key, Sallyport.private_key
    assert_equal public_key, Sallyport.public_key(private_key)
    assert_raises(ArgumentError) { Sallyport.public_key("c2hvcnQ=") }
    assert_raises(ArgumentError) { Sallyport.public_key(nil) }
  end
end

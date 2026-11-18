# frozen_string_literal: true

require_relative "helper"

class TestSallyport < Minitest::Test
  def test_the_library_loads_and_is_the_gems_version
    assert_equal Sallyport::VERSION, Sallyport::Native::VERSION.call.to_s
  end
end

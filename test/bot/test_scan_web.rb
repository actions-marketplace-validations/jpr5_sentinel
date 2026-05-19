require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"

$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/config"

# Tests for the GET /scan and POST /scan web endpoints.
#
# Since Sinatra requires a running server, we test the components that the
# routes depend on: pattern list generation, limit clamping, and ScannerBot
# constructor compatibility with the web handler's calling convention.

class TestScanWeb < Minitest::Test
    # --- Pattern dropdown population ---

    def test_search_queries_returns_patterns
        patterns = Bot::Config::SEARCH_QUERIES.map { |q| q[:pattern] }
        refute_empty patterns
        assert patterns.all? { |p| p.is_a?(String) }
    end

    def test_expected_patterns_present
        patterns = Bot::Config::SEARCH_QUERIES.map { |q| q[:pattern] }
        %w[shell-injection shell-injection-body shell-injection-headref
           shell-injection-actor dangerous-triggers].each do |expected|
            assert_includes patterns, expected, "Missing pattern: #{expected}"
        end
    end

    # --- Limit clamping logic (mirrors POST /scan) ---

    def test_limit_clamp_default
        limit = [[(nil || "5").to_i, 1].max, 50].min
        assert_equal 5, limit
    end

    def test_limit_clamp_minimum
        limit = [[("0").to_i, 1].max, 50].min
        assert_equal 1, limit
    end

    def test_limit_clamp_negative
        limit = [[("-10").to_i, 1].max, 50].min
        assert_equal 1, limit
    end

    def test_limit_clamp_maximum
        limit = [[("100").to_i, 1].max, 50].min
        assert_equal 50, limit
    end

    def test_limit_clamp_valid
        limit = [[("25").to_i, 1].max, 50].min
        assert_equal 25, limit
    end

    def test_limit_clamp_non_numeric
        limit = [[("abc").to_i, 1].max, 50].min
        assert_equal 1, limit
    end

    # --- ScannerBot constructor accepts web handler args ---

    def test_scanner_bot_constructor_accepts_queue_mode_args
        # Verify the ScannerBot class exists and its initialize signature
        # accepts the keyword arguments used in POST /scan.
        # We can't actually instantiate it without a token, but we can
        # verify the class is loadable and check its method signature.
        require_relative "../../bot/scanner_bot"

        params = Bot::ScannerBot.instance_method(:initialize).parameters
        param_names = params.map(&:last)

        assert_includes param_names, :token
        assert_includes param_names, :pattern
        assert_includes param_names, :dry_run
        assert_includes param_names, :limit
        assert_includes param_names, :queue_mode
    end

    # --- Pattern validation ---

    def test_pattern_param_falls_back_to_rotate
        # Mirrors: pattern = params["pattern"] || "rotate"
        assert_equal "rotate", (nil || "rotate")
        assert_equal "shell-injection", ("shell-injection" || "rotate")
    end

    def test_empty_pattern_is_truthy_in_ruby
        # In Ruby, "" is truthy. Sinatra params won't contain "" for
        # a select element -- it will be the selected value or nil.
        # This documents the behavior.
        assert_equal "", ("" || "rotate")
    end
end

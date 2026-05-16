require_relative "test_helper"
require "net/http"
require "json"

class TestShaResolver < Minitest::Test
    def test_initialize_with_token
        resolver = ShaResolver.new(token: "ghp_test123")
        assert_instance_of ShaResolver, resolver
    end

    def test_initialize_without_token_uses_env
        original = ENV["GITHUB_TOKEN"]
        begin
            ENV["GITHUB_TOKEN"] = "ghp_from_env"
            resolver = ShaResolver.new
            assert_instance_of ShaResolver, resolver
        ensure
            if original
                ENV["GITHUB_TOKEN"] = original
            else
                ENV.delete("GITHUB_TOKEN")
            end
        end
    end

    def test_initialize_without_token_or_env
        original = ENV["GITHUB_TOKEN"]
        begin
            ENV.delete("GITHUB_TOKEN")
            resolver = ShaResolver.new
            assert_instance_of ShaResolver, resolver
        ensure
            if original
                ENV["GITHUB_TOKEN"] = original
            else
                ENV.delete("GITHUB_TOKEN")
            end
        end
    end

    def test_cache_returns_same_result_without_second_api_call
        resolver = ShaResolver.new(token: "ghp_test")
        fake_sha = "abc123def456789012345678901234567890abcd"
        call_count = 0

        # Stub fetch_sha to count calls
        resolver.define_singleton_method(:resolve) do |owner_action, tag|
            repo = owner_action.split("/")[0..1].join("/")
            key = "#{repo}@#{tag}"
            @cache[key] ||= begin
                call_count += 1
                fake_sha
            end
        end

        result1 = resolver.resolve("actions/checkout", "v4")
        result2 = resolver.resolve("actions/checkout", "v4")

        assert_equal fake_sha, result1
        assert_equal fake_sha, result2
        assert_equal 1, call_count, "Expected fetch to be called only once due to caching"
    end

    def test_cache_different_tags_are_separate_entries
        resolver = ShaResolver.new(token: "ghp_test")
        call_count = 0

        resolver.define_singleton_method(:resolve) do |owner_action, tag|
            repo = owner_action.split("/")[0..1].join("/")
            key = "#{repo}@#{tag}"
            @cache[key] ||= begin
                call_count += 1
                "sha_for_#{tag}"
            end
        end

        result1 = resolver.resolve("actions/checkout", "v3")
        result2 = resolver.resolve("actions/checkout", "v4")

        assert_equal "sha_for_v3", result1
        assert_equal "sha_for_v4", result2
        assert_equal 2, call_count
    end

    def test_extract_repo_handles_subpath_actions
        resolver = ShaResolver.new(token: "ghp_test")
        result = resolver.send(:extract_repo, "actions/cache/restore")
        assert_equal "actions/cache", result
    end

    def test_extract_repo_handles_normal_actions
        resolver = ShaResolver.new(token: "ghp_test")
        result = resolver.send(:extract_repo, "pnpm/action-setup")
        assert_equal "pnpm/action-setup", result
    end

    def test_extract_repo_handles_deep_subpath
        resolver = ShaResolver.new(token: "ghp_test")
        result = resolver.send(:extract_repo, "org/repo/sub/deep/path")
        assert_equal "org/repo", result
    end

    def test_fetch_sha_returns_sha_on_200
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(code: "200", body: JSON.generate({ "sha" => "abcdef1234567890" }))

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_equal "abcdef1234567890", result
        end
    end

    def test_fetch_sha_returns_nil_on_404
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(code: "404")

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "nonexistent")
            assert_nil result
        end
    end

    def test_fetch_sha_returns_nil_on_403
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(code: "403")

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_nil result
        end
    end

    def test_fetch_sha_returns_nil_on_500
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(code: "500")

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_nil result
        end
    end

    def test_fetch_sha_returns_nil_on_network_error
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(raise_error: SocketError.new("getaddrinfo: Name or service not known"))

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_nil result
        end
    end

    def test_fetch_sha_returns_nil_on_timeout
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(raise_error: Net::OpenTimeout.new("execution expired"))

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_nil result
        end
    end

    def test_fetch_sha_returns_nil_on_connection_refused
        resolver = ShaResolver.new(token: "ghp_test")
        mock_http = make_mock_http(raise_error: Errno::ECONNREFUSED.new("Connection refused"))

        stub_http_new(mock_http) do
            result = resolver.send(:fetch_sha, "actions/checkout", "v4")
            assert_nil result
        end
    end

    def test_authorization_header_set_when_token_provided
        resolver = ShaResolver.new(token: "ghp_test_token_123")
        captured_req = nil
        fake_response = make_fake_response(code: "200", body: JSON.generate({ "sha" => "abc123" }))

        mock_http = Object.new
        mock_http.define_singleton_method(:use_ssl=) { |_| }
        mock_http.define_singleton_method(:open_timeout=) { |_| }
        mock_http.define_singleton_method(:read_timeout=) { |_| }
        mock_http.define_singleton_method(:request) { |req| captured_req = req; fake_response }

        stub_http_new(mock_http) do
            resolver.send(:fetch_sha, "actions/checkout", "v4")
        end

        assert_equal "Bearer ghp_test_token_123", captured_req["Authorization"]
    end

    def test_api_version_header_set
        resolver = ShaResolver.new(token: "ghp_test")
        captured_req = nil
        fake_response = make_fake_response(code: "200", body: JSON.generate({ "sha" => "abc" }))

        mock_http = Object.new
        mock_http.define_singleton_method(:use_ssl=) { |_| }
        mock_http.define_singleton_method(:open_timeout=) { |_| }
        mock_http.define_singleton_method(:read_timeout=) { |_| }
        mock_http.define_singleton_method(:request) { |req| captured_req = req; fake_response }

        stub_http_new(mock_http) do
            resolver.send(:fetch_sha, "actions/checkout", "v4")
        end

        assert_equal "2022-11-28", captured_req["X-GitHub-Api-Version"]
    end

    def test_accept_header_set
        resolver = ShaResolver.new(token: "ghp_test")
        captured_req = nil
        fake_response = make_fake_response(code: "200", body: JSON.generate({ "sha" => "abc" }))

        mock_http = Object.new
        mock_http.define_singleton_method(:use_ssl=) { |_| }
        mock_http.define_singleton_method(:open_timeout=) { |_| }
        mock_http.define_singleton_method(:read_timeout=) { |_| }
        mock_http.define_singleton_method(:request) { |req| captured_req = req; fake_response }

        stub_http_new(mock_http) do
            resolver.send(:fetch_sha, "actions/checkout", "v4")
        end

        assert_equal "application/vnd.github+json", captured_req["Accept"]
    end

    private

    def make_fake_response(code:, body: "")
        resp = Object.new
        resp.define_singleton_method(:code) { code }
        resp.define_singleton_method(:body) { body }
        resp
    end

    def make_mock_http(code: nil, body: "", raise_error: nil)
        fake_response = make_fake_response(code: code || "200", body: body) unless raise_error
        err = raise_error

        mock = Object.new
        mock.define_singleton_method(:use_ssl=) { |_| }
        mock.define_singleton_method(:open_timeout=) { |_| }
        mock.define_singleton_method(:read_timeout=) { |_| }
        if err
            mock.define_singleton_method(:request) { |_req| raise err }
        else
            mock.define_singleton_method(:request) { |_req| fake_response }
        end
        mock
    end

    def stub_http_new(mock_http)
        original_new = Net::HTTP.method(:new)
        Net::HTTP.define_singleton_method(:new) { |*_args| mock_http }
        begin
            # Suppress stderr from ShaResolver error messages
            original_stderr = $stderr
            $stderr = StringIO.new
            yield
        ensure
            $stderr = original_stderr
            Net::HTTP.define_singleton_method(:new, original_new)
        end
    end
end

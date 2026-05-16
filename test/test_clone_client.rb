require_relative "test_helper"
require "tmpdir"
require "fileutils"

class TestCloneClient < Minitest::Test
    def test_initialize_does_not_crash
        client = CloneClient.new
        assert_instance_of CloneClient, client
    end

    def test_cleanup_removes_temp_dir
        client = CloneClient.new

        # Simulate a tmpdir being set by reaching into internals
        tmpdir = Dir.mktmpdir("sentinel-test-cleanup-")
        client.instance_variable_set(:@tmpdir, tmpdir)

        assert File.directory?(tmpdir), "tmpdir should exist before cleanup"
        client.cleanup
        refute File.directory?(tmpdir), "tmpdir should be removed after cleanup"
    end

    def test_cleanup_noop_when_no_tmpdir
        client = CloneClient.new
        # Should not raise
        client.cleanup
    end

    def test_invalid_repo_format_returns_empty
        client = CloneClient.new

        # Path traversal attempt
        result = client.fetch_workflows("../../../etc/passwd")
        assert_equal [], result

        # Shell metacharacters
        result = client.fetch_workflows("owner/repo; rm -rf /")
        assert_equal [], result

        # Empty string
        result = client.fetch_workflows("")
        assert_equal [], result
    end

    def test_valid_repo_format_accepted
        # Test that the regex accepts valid repo names
        assert "owner/repo".match?(CloneClient::REPO_FORMAT)
        assert "my-org/my-repo.rb".match?(CloneClient::REPO_FORMAT)
        assert "Org_123/Repo-456".match?(CloneClient::REPO_FORMAT)
    end

    def test_invalid_repo_format_rejected
        refute "".match?(CloneClient::REPO_FORMAT)
        refute "just-a-name".match?(CloneClient::REPO_FORMAT)
        refute "owner/repo/extra".match?(CloneClient::REPO_FORMAT)
        refute "owner/repo; rm -rf /".match?(CloneClient::REPO_FORMAT)
        refute "../etc/passwd".match?(CloneClient::REPO_FORMAT)
    end

    def test_file_exists_returns_false_without_clone
        client = CloneClient.new
        refute client.file_exists?("owner/repo", ".github/workflows/ci.yml")
    end

    def test_fetch_dependabot_config_returns_nil_without_clone
        client = CloneClient.new
        assert_nil client.fetch_dependabot_config("owner/repo")
    end

    def test_clone_scan_public_repo
        # Integration test — clones a real public repo
        # Skip in CI or if git is not available
        skip "Integration test — set RUN_INTEGRATION=1 to enable" unless ENV["RUN_INTEGRATION"]

        client = CloneClient.new
        begin
            workflows = client.fetch_workflows("jpr5/sentinel")
            assert_kind_of Array, workflows
            # The repo should have at least one workflow
            refute_empty workflows, "Expected at least one workflow from jpr5/sentinel"
            workflows.each do |w|
                assert w[:filename], "Each workflow should have a filename"
                assert w[:content], "Each workflow should have content"
            end
        ensure
            client.cleanup
        end
    end

    def test_clone_nonexistent_repo_returns_empty
        # This test actually tries to clone — it should fail gracefully
        # Use a repo name that definitely doesn't exist
        client = CloneClient.new
        begin
            result = client.fetch_workflows("nonexistent-owner-abc123/nonexistent-repo-xyz789")
            assert_equal [], result
        ensure
            client.cleanup
        end
    end
end

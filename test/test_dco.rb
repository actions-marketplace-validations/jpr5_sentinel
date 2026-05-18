require "minitest/autorun"
require_relative "test_helper"

# Pull in Bot modules
$LOAD_PATH.unshift(File.join(__dir__, "..", "bot"))
require_relative "../bot/config"
require_relative "../bot/repo_conventions"

# Simple stub GitHubClient for DCO tests
class DcoStubClient
    attr_accessor :file_exists_map, :file_content_map

    def initialize(token: nil)
        @file_exists_map = {}
        @file_content_map = {}
    end

    def file_exists?(repo, path)
        @file_exists_map[[repo, path]] || false
    end

    def fetch_file_content(repo, path)
        @file_content_map[[repo, path]]
    end
end

class TestDco < Minitest::Test
    def setup
        @stub_client = DcoStubClient.new
        @original_new = GitHubClient.method(:new)
        stub_github_client!
        @conventions = Bot::RepoConventions.new(token: "fake-token")
    end

    def teardown
        # Restore original GitHubClient.new
        original = @original_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
    end

    def stub_github_client!
        stub = @stub_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }
    end

    # ── requires_dco? (now via RepoConventions) ─────────────────────────────

    def test_dco_detected_via_dco_yml
        @stub_client.file_exists_map[["owner/repo", ".github/dco.yml"]] = true
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_detected_via_contributing_md
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] = "Please sign-off your commits (DCO required)."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_detected_via_signed_off_by_in_contributing
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] = "All commits must include a Signed-off-by line."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_detected_via_sign_off_in_contributing
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] = "You must sign off on every commit."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_detected_via_contributing_no_extension
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING"]] = "This project uses DCO for contributions."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_not_required_when_nothing_found
        refute @conventions.requires_dco?("owner/repo")
    end

    def test_dco_not_required_when_contributing_has_no_dco_mention
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] = "Please follow our coding guidelines."
        refute @conventions.requires_dco?("owner/repo")
    end

    # ── Config constant ──────────────────────────────────────────────────────

    def test_config_signoff_identity_exists
        assert_equal "Jordan Ritter <jpr5@darkridge.com>", Bot::Config::SIGNOFF_IDENTITY
    end
end

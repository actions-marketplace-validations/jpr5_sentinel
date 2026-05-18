require "minitest/autorun"
require_relative "test_helper"

# Pull in Bot modules
$LOAD_PATH.unshift(File.join(__dir__, "..", "bot"))
require_relative "../bot/config"
require_relative "../bot/repo_conventions"

# Stub GitHubClient for convention detection tests
class ConventionStubClient
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

class TestRepoConventions < Minitest::Test
    def setup
        @stub_client = ConventionStubClient.new
        @original_new = GitHubClient.method(:new)
        stub_github_client!
        @conventions = Bot::RepoConventions.new(token: "fake-token")
    end

    def teardown
        original = @original_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
    end

    def stub_github_client!
        stub = @stub_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }
    end

    # ── CLA detection ────────────────────────────────────────────────────────

    def test_detect_google_cla
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "You must sign the Google CLA before we can accept your contribution."
        assert_equal :google, @conventions.detect_cla("owner/repo")
    end

    def test_detect_google_cla_via_url
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Please sign at cla/google before submitting."
        assert_equal :google, @conventions.detect_cla("owner/repo")
    end

    def test_detect_apache_cla
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Contributors must sign the Apache CLA."
        assert_equal :apache, @conventions.detect_cla("owner/repo")
    end

    def test_detect_apache_icla
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "An ICLA is required for all contributors."
        assert_equal :apache, @conventions.detect_cla("owner/repo")
    end

    def test_detect_generic_cla
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "You must sign a Contributor License Agreement before contributing."
        assert_equal :generic, @conventions.detect_cla("owner/repo")
    end

    def test_detect_generic_cla_sign
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Please complete the CLA sign-up process."
        assert_equal :generic, @conventions.detect_cla("owner/repo")
    end

    def test_no_cla_when_contributing_missing
        assert_nil @conventions.detect_cla("owner/repo")
    end

    def test_no_cla_when_contributing_has_no_cla_mention
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Thanks for contributing! Please follow our coding guidelines."
        assert_nil @conventions.detect_cla("owner/repo")
    end

    def test_cla_detected_in_contributing_no_extension
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING"]] =
            "You must sign the Google CLA."
        assert_equal :google, @conventions.detect_cla("owner/repo")
    end

    def test_cla_detected_in_contributing_lowercase
        @stub_client.file_content_map[["owner/repo", "contributing.md"]] =
            "Please sign a Contributor License Agreement."
        assert_equal :generic, @conventions.detect_cla("owner/repo")
    end

    # ── Conventional commits detection ───────────────────────────────────────

    def test_conventional_commits_via_commitlintrc
        @stub_client.file_exists_map[["owner/repo", ".commitlintrc"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_commitlintrc_js
        @stub_client.file_exists_map[["owner/repo", ".commitlintrc.js"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_commitlintrc_json
        @stub_client.file_exists_map[["owner/repo", ".commitlintrc.json"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_commitlintrc_yml
        @stub_client.file_exists_map[["owner/repo", ".commitlintrc.yml"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_config_js
        @stub_client.file_exists_map[["owner/repo", "commitlint.config.js"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_config_ts
        @stub_client.file_exists_map[["owner/repo", "commitlint.config.ts"]] = true
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_contributing_mention
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "We use conventional commit messages for all PRs."
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_conventional_commits_via_commitlint_mention
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "This project enforces commitlint rules."
        assert @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_no_conventional_commits
        refute @conventions.requires_conventional_commits?("owner/repo")
    end

    def test_no_conventional_commits_unrelated_contributing
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Please write clear commit messages."
        refute @conventions.requires_conventional_commits?("owner/repo")
    end

    # ── PR template detection ────────────────────────────────────────────────

    def test_pr_template_github_uppercase
        @stub_client.file_exists_map[["owner/repo", ".github/PULL_REQUEST_TEMPLATE.md"]] = true
        assert @conventions.has_pr_template?("owner/repo")
    end

    def test_pr_template_github_lowercase
        @stub_client.file_exists_map[["owner/repo", ".github/pull_request_template.md"]] = true
        assert @conventions.has_pr_template?("owner/repo")
    end

    def test_pr_template_root
        @stub_client.file_exists_map[["owner/repo", "PULL_REQUEST_TEMPLATE.md"]] = true
        assert @conventions.has_pr_template?("owner/repo")
    end

    def test_no_pr_template
        refute @conventions.has_pr_template?("owner/repo")
    end

    # ── DCO detection (delegated) ────────────────────────────────────────────

    def test_dco_via_dco_yml
        @stub_client.file_exists_map[["owner/repo", ".github/dco.yml"]] = true
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_via_contributing_md
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Please sign-off your commits (DCO required)."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_via_signed_off_by
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "All commits must include a Signed-off-by line."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_dco_via_contributing_no_extension
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING"]] =
            "This project uses DCO for contributions."
        assert @conventions.requires_dco?("owner/repo")
    end

    def test_no_dco
        refute @conventions.requires_dco?("owner/repo")
    end

    # ── Full detect method ───────────────────────────────────────────────────

    def test_detect_returns_all_conventions
        @stub_client.file_exists_map[["owner/repo", ".github/dco.yml"]] = true
        @stub_client.file_exists_map[["owner/repo", ".commitlintrc.json"]] = true
        @stub_client.file_exists_map[["owner/repo", ".github/PULL_REQUEST_TEMPLATE.md"]] = true
        @stub_client.file_content_map[["owner/repo", "CONTRIBUTING.md"]] =
            "Sign the Google CLA before contributing."

        result = @conventions.detect("owner/repo")

        assert_equal true, result[:dco]
        assert_equal :google, result[:cla]
        assert_equal true, result[:conventional_commits]
        assert_equal true, result[:pr_template]
    end

    def test_detect_returns_all_nil_or_false_for_clean_repo
        result = @conventions.detect("owner/repo")

        assert_equal false, result[:dco]
        assert_nil result[:cla]
        assert_equal false, result[:conventional_commits]
        assert_equal false, result[:pr_template]
    end
end

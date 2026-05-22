require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"

# Load bot modules
$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/scanner_bot"

# ============================================================================
# Stub classes (same pattern as test_scanner_bot_integration.rb)
# ============================================================================

class OrgReposStubGitHubClient
    attr_accessor :file_exists_map, :file_content_map, :workflows

    def initialize(token: nil)
        @file_exists_map = {}
        @file_content_map = {}
        @workflows = []
    end

    def file_exists?(repo, path)
        @file_exists_map[[repo, path]] || false
    end

    def fetch_file_content(repo, path)
        @file_content_map[[repo, path]]
    end

    def fetch_workflows(repo)
        @workflows
    end

    def fetch_dependabot_config(repo)
        nil
    end
end

class OrgReposStubSearch
    attr_accessor :candidates

    def initialize(token: nil)
        @candidates = []
    end

    def find_candidates(_query)
        @candidates
    end
end

class OrgReposStubScanner
    attr_accessor :scan_results

    def initialize
        @scan_results = {}
    end

    def scan(repo)
        @scan_results[repo] || { findings: [], output: "", workflow_count: 0, workflows: [] }
    end
end

class OrgReposStubPrWriter
    def initialize(token: nil); end
    def create_pr(**kwargs); nil; end
    def create_issue(**kwargs); nil; end
end

class OrgReposStubSync
    def initialize(token: nil, state: nil); end

    def sync_all
        { synced: 0, updated: 0, errors: 0 }
    end
end

# ============================================================================
# Tests for ORG_REPOS
# ============================================================================

class TestOrgRepos < Minitest::Test
    EXPECTED_ORG_REPOS = %w[
        CopilotKit/CopilotKit
        CopilotKit/aimock
        CopilotKit/skills
        CopilotKit/pathfinder
        CopilotKit/vscode-extension
        ag-ui-protocol/ag-ui
    ].freeze

    def setup
        @tmpdir = Dir.mktmpdir("sentinel-org-repos-test")
        @state_file = File.join(@tmpdir, "state.json")
        @queue_file = File.join(@tmpdir, "queue.json")
        @audit_file = File.join(@tmpdir, "audit.log")

        @stub_gh_client = OrgReposStubGitHubClient.new
        @stub_search = OrgReposStubSearch.new
        @stub_scanner = OrgReposStubScanner.new

        @original_gh_new = GitHubClient.method(:new)
        stub = @stub_gh_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
        original = @original_gh_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
    end

    # ---------------------------------------------------------------
    # Test 1: ORG_REPOS contains the 6 expected repos
    # ---------------------------------------------------------------
    def test_org_repos_contains_expected_repos
        assert_equal EXPECTED_ORG_REPOS.sort, Bot::Config::ORG_REPOS.sort
        assert_equal 6, Bot::Config::ORG_REPOS.length
    end

    # ---------------------------------------------------------------
    # Test 2: ORG_REPOS does NOT contain sentinel-canary
    # ---------------------------------------------------------------
    def test_org_repos_excludes_sentinel_canary
        refute_includes Bot::Config::ORG_REPOS, "jpr5/sentinel-canary"
        Bot::Config::ORG_REPOS.each do |repo|
            refute_match(/sentinel-canary/, repo)
        end
    end

    # ---------------------------------------------------------------
    # Test 3: Bot run with no --repos includes all ORG_REPOS in scan list
    # ---------------------------------------------------------------
    def test_default_run_includes_all_org_repos
        # Search returns no external candidates — so the only candidates
        # the bot should scan are the ORG_REPOS.
        @stub_search.candidates = []

        bot = build_bot(dry_run: true)
        scanned_repos = []

        # Intercept scan_and_fix to capture which repos are scanned
        bot.define_singleton_method(:scan_and_fix) do |repo, pattern|
            scanned_repos << repo[:full_name]
        end

        capture_io { bot.run }

        EXPECTED_ORG_REPOS.each do |repo|
            assert_includes scanned_repos, repo, "Expected #{repo} to be scanned as org backstop"
        end
    end

    # ---------------------------------------------------------------
    # Test 4: ORG_REPOS are NOT subject to min_stars filter
    # ---------------------------------------------------------------
    def test_org_repos_bypass_min_stars_filter
        # Search returns external candidates (which went through min_stars
        # in Search#find_candidates). ORG_REPOS are prepended with stars: 0,
        # which would fail MIN_STARS=100 if they went through the filter.
        @stub_search.candidates = [
            { full_name: "external/popular-repo", stars: 500 }
        ]

        bot = build_bot(dry_run: true)
        scanned_repos = []

        bot.define_singleton_method(:scan_and_fix) do |repo, pattern|
            scanned_repos << repo
        end

        capture_io { bot.run }

        # All org repos should be present despite stars: 0
        EXPECTED_ORG_REPOS.each do |repo_name|
            entry = scanned_repos.find { |r| r[:full_name] == repo_name }
            assert entry, "Expected #{repo_name} in scan list despite 0 stars"
            assert_equal 0, entry[:stars], "Org repo #{repo_name} should have stars: 0 (bypassed min_stars)"
            assert entry[:org_repo], "Org repo #{repo_name} should be tagged as org_repo"
        end

        # External repo should also be present
        external = scanned_repos.find { |r| r[:full_name] == "external/popular-repo" }
        assert external, "External repo should also be in scan list"
    end

    # ---------------------------------------------------------------
    # Test 5: ORG_REPOS appear before search candidates (priority)
    # ---------------------------------------------------------------
    def test_org_repos_scanned_before_search_candidates
        @stub_search.candidates = [
            { full_name: "external/repo-a", stars: 200 },
            { full_name: "external/repo-b", stars: 150 }
        ]

        bot = build_bot(dry_run: true)
        scan_order = []

        bot.define_singleton_method(:scan_and_fix) do |repo, pattern|
            scan_order << repo[:full_name]
        end

        capture_io { bot.run }

        # First 6 should be the org repos
        org_section = scan_order[0, EXPECTED_ORG_REPOS.length]
        external_section = scan_order[EXPECTED_ORG_REPOS.length..]

        EXPECTED_ORG_REPOS.each do |repo|
            assert_includes org_section, repo, "Org repo #{repo} should be scanned before external repos"
        end

        assert_includes external_section, "external/repo-a"
        assert_includes external_section, "external/repo-b"
    end

    # ---------------------------------------------------------------
    # Test 6: Deduplication — org repo found by search is not scanned twice
    # ---------------------------------------------------------------
    def test_org_repos_deduplicated_with_search_results
        # Simulate search finding one of the org repos
        @stub_search.candidates = [
            { full_name: "CopilotKit/CopilotKit", stars: 10000 },
            { full_name: "external/other-repo", stars: 300 }
        ]

        bot = build_bot(dry_run: true)
        scanned_repos = []

        bot.define_singleton_method(:scan_and_fix) do |repo, pattern|
            scanned_repos << repo[:full_name]
        end

        capture_io { bot.run }

        # CopilotKit/CopilotKit should appear exactly once
        copilotkit_count = scanned_repos.count("CopilotKit/CopilotKit")
        assert_equal 1, copilotkit_count, "CopilotKit/CopilotKit should appear exactly once (dedup)"

        # Total should be 6 org + 1 external (not 6 + 2 since CopilotKit was deduped)
        assert_equal EXPECTED_ORG_REPOS.length + 1, scanned_repos.length
    end

    # ---------------------------------------------------------------
    # Test 7: --repos flag still works and does NOT add org repos
    # ---------------------------------------------------------------
    def test_targeted_repos_flag_does_not_add_org_repos
        bot = nil
        capture_io do
            bot = Bot::ScannerBot.new(
                token: "fake-token",
                pattern: "shell-injection",
                dry_run: true,
                repos: "some/target-repo"
            )
        end

        bot.instance_variable_set(:@search, @stub_search)
        bot.instance_variable_set(:@scanner, @stub_scanner)
        bot.instance_variable_set(:@pr_writer, OrgReposStubPrWriter.new)
        bot.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))
        bot.instance_variable_set(:@audit, Bot::Audit.new(@audit_file))

        sync_stub = OrgReposStubSync.new
        bot.define_singleton_method(:sync_pr_statuses) { sync_stub.sync_all }

        scanned_repos = []
        bot.define_singleton_method(:scan_and_fix) do |repo, pattern|
            scanned_repos << repo[:full_name]
        end

        capture_io { bot.run }

        assert_equal ["some/target-repo"], scanned_repos,
            "--repos should only scan targeted repos, not add org repos"
    end

    private

    def build_bot(pattern: "shell-injection", dry_run: false, queue_mode: false, limit: nil)
        bot = nil
        capture_io do
            bot = Bot::ScannerBot.new(
                token: "fake-token",
                pattern: pattern,
                dry_run: dry_run,
                limit: limit,
                queue_mode: queue_mode
            )
        end

        bot.instance_variable_set(:@search, @stub_search)
        bot.instance_variable_set(:@scanner, @stub_scanner)
        bot.instance_variable_set(:@pr_writer, OrgReposStubPrWriter.new)
        bot.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))
        bot.instance_variable_set(:@audit, Bot::Audit.new(@audit_file))

        sync_stub = OrgReposStubSync.new
        bot.define_singleton_method(:sync_pr_statuses) { sync_stub.sync_all }

        bot
    end
end

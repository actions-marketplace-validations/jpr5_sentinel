require "minitest/autorun"
require "json"
require "time"
require "uri"

require_relative "../../bot/config"
require_relative "../../bot/state"
require_relative "../../bot/bootstrap"

# Stub State that tracks calls without needing a real file
class BootstrapStubState
    attr_reader :recorded_prs, :status_updates

    def initialize(tracked_prs = [])
        @tracked_prs = tracked_prs  # Array of {repo:, pr: {hash}}
        @recorded_prs = []
        @status_updates = []
    end

    def all_tracked_prs
        @tracked_prs
    end

    def record_pr(repo_name, pr_url, rule, number)
        entry = {
            "url" => pr_url,
            "number" => number,
            "rule" => rule,
            "status" => "open",
            "note" => nil,
            "created_at" => Time.now.utc.iso8601,
            "last_updated_at" => Time.now.utc.iso8601,
            "synced_at" => nil,
        }
        @tracked_prs << { repo: repo_name, pr: entry }
        @recorded_prs << { repo: repo_name, url: pr_url, rule: rule, number: number }
    end

    def update_pr_status(repo_name, number, status, note: nil)
        @status_updates << { repo: repo_name, number: number, status: status, note: note }
        entry = @tracked_prs.find { |e| e[:repo] == repo_name && e[:pr]["number"] == number }
        if entry
            entry[:pr]["status"] = status
            entry[:pr]["note"] = note
        end
    end
end

class TestBotBootstrap < Minitest::Test
    def setup
        @token = "test-token"
    end

    # Helper: decode path for pattern matching in stubs.
    # The search API URL-encodes query params, so org:CopilotKit becomes org%3ACopilotKit.
    def decoded(path)
        URI.decode_www_form_component(path)
    end

    # Helper: build a search result item (issue/PR from search API)
    # Includes body and head ref fields that the post-filter checks.
    def search_item(repo:, number:, state: "open", merged_at: nil,
                    title: "Security: Fix 3 findings in GitHub Actions workflows",
                    body: "Automated fixes from Sentinel Bot\nhttps://sentinel.copilotkit.dev",
                    head_ref: "sentinel/security-fixes")
        {
            "html_url" => "https://github.com/#{repo}/pull/#{number}",
            "number" => number,
            "title" => title,
            "body" => body,
            "state" => state,
            "created_at" => "2026-05-01T00:00:00Z",
            "updated_at" => "2026-05-10T00:00:00Z",
            "pull_request" => {
                "merged_at" => merged_at,
                "head" => { "ref" => head_ref },
            },
        }
    end

    # Helper: build a pulls API response item
    def pulls_item(number:, state: "open", merged_at: nil, head_ref: "sentinel/security-fixes")
        {
            "number" => number,
            "html_url" => "https://github.com/owner/repo/pull/#{number}",
            "state" => state,
            "merged_at" => merged_at,
            "merged" => !merged_at.nil?,
            "created_at" => "2026-05-01T00:00:00Z",
            "updated_at" => "2026-05-10T00:00:00Z",
            "head" => { "ref" => head_ref },
        }
    end

    # Helper: create a bootstrap with a stubbed api_get that routes based on decoded path.
    # Also stubs sleep to avoid test slowness.
    def make_bootstrap(state:, &block)
        bootstrap = Bot::Bootstrap.new(token: @token, state: state)
        bootstrap.define_singleton_method(:api_get, &block)
        bootstrap.define_singleton_method(:sleep) { |_| }  # no-op in tests
        bootstrap
    end

    # -------------------------------------------------------
    # Test 1: Discovers PRs from search API
    # -------------------------------------------------------
    def test_discovers_prs_from_search_api
        state = BootstrapStubState.new

        open_pr = search_item(repo: "CopilotKit/CopilotKit", number: 4820, state: "open")
        merged_pr = search_item(repo: "CopilotKit/runtime", number: 100, state: "closed", merged_at: "2026-05-05T00:00:00Z")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 2, "items" => [open_pr, merged_pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 2, result[:found]
        assert_equal 2, result[:new]
        assert_equal 0, result[:already_tracked]

        # Verify record_pr was called
        assert_equal 2, state.recorded_prs.length

        # Check the merged PR had its status updated
        merged_update = state.status_updates.find { |u| u[:number] == 100 }
        refute_nil merged_update
        assert_equal "merged", merged_update[:status]
    end

    # -------------------------------------------------------
    # Test 2: Skips already-tracked PRs
    # -------------------------------------------------------
    def test_skips_already_tracked_prs
        existing_pr = {
            "url" => "https://github.com/CopilotKit/CopilotKit/pull/4820",
            "number" => 4820,
            "rule" => "unpinned-actions",
            "status" => "open",
            "note" => nil,
            "created_at" => "2026-05-01T00:00:00Z",
            "last_updated_at" => "2026-05-01T00:00:00Z",
            "synced_at" => nil,
        }
        state = BootstrapStubState.new([{ repo: "CopilotKit/CopilotKit", pr: existing_pr }])

        search_result = search_item(repo: "CopilotKit/CopilotKit", number: 4820, state: "open")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 1, "items" => [search_result] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 1, result[:found]
        assert_equal 0, result[:new]
        assert_equal 1, result[:already_tracked]
        assert_empty state.recorded_prs
    end

    # -------------------------------------------------------
    # Test 3: Records new PRs with correct status
    # -------------------------------------------------------
    def test_records_new_prs_with_correct_status
        state = BootstrapStubState.new

        open_pr = search_item(repo: "CopilotKit/CopilotKit", number: 100, state: "open")
        merged_pr = search_item(repo: "CopilotKit/CopilotKit", number: 200, state: "closed", merged_at: "2026-05-05T00:00:00Z")
        closed_pr = search_item(repo: "CopilotKit/CopilotKit", number: 300, state: "closed", merged_at: nil)

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 3, "items" => [open_pr, merged_pr, closed_pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        bootstrap.run

        # All three should be recorded with "multiple" as the rule
        assert_equal 3, state.recorded_prs.length
        state.recorded_prs.each do |pr|
            assert_equal "multiple", pr[:rule]
        end

        # Check status updates
        open_update = state.status_updates.find { |u| u[:number] == 100 }
        merged_update = state.status_updates.find { |u| u[:number] == 200 }
        closed_update = state.status_updates.find { |u| u[:number] == 300 }

        assert_equal "open", open_update[:status]
        assert_equal "merged", merged_update[:status]
        assert_equal "closed", closed_update[:status]
    end

    # -------------------------------------------------------
    # Test 4: Handles API errors gracefully
    # -------------------------------------------------------
    def test_handles_api_errors_gracefully
        state = BootstrapStubState.new

        bootstrap = make_bootstrap(state: state) do |path|
            nil
        end

        result = bootstrap.run
        assert_equal 0, result[:found]
        assert_equal 0, result[:new]
        # Both org searches should count as errors
        assert_equal 2, result[:errors]
    end

    # -------------------------------------------------------
    # Test 5: Pagination works
    # -------------------------------------------------------
    def test_pagination_works
        state = BootstrapStubState.new

        page1_items = (1..100).map do |i|
            search_item(repo: "CopilotKit/repo#{i}", number: i, state: "open")
        end

        page2_items = [
            search_item(repo: "CopilotKit/repo101", number: 101, state: "open"),
        ]

        call_count = { copilotkit: 0 }

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                call_count[:copilotkit] += 1
                if path.include?("page=2")
                    { "total_count" => 101, "items" => page2_items }
                else
                    { "total_count" => 101, "items" => page1_items }
                end
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        # Should have found items — deduped across the two search queries
        assert result[:found] > 0
        # Pagination should have been triggered (more than 2 calls to CopilotKit search)
        assert call_count[:copilotkit] > 2, "Should paginate when 100 results returned"
    end

    # -------------------------------------------------------
    # Test 6: Deduplicates PRs found from multiple searches
    # -------------------------------------------------------
    def test_deduplicates_prs_across_searches
        state = BootstrapStubState.new

        # Same PR returned from both "Security:" and "Add Sentinel" queries
        pr = search_item(repo: "CopilotKit/CopilotKit", number: 42, state: "open")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 1, "items" => [pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        # Should only count once despite appearing in multiple search results
        assert_equal 1, result[:found]
        assert_equal 1, result[:new]
        assert_equal 1, state.recorded_prs.length
    end

    # -------------------------------------------------------
    # Test 7: Checks repos from state that aren't in known orgs
    # -------------------------------------------------------
    def test_checks_state_repos_outside_known_orgs
        existing_pr = {
            "url" => "https://github.com/jpr5/vulnerable-workflows-test/pull/1",
            "number" => 1,
            "rule" => "unpinned-actions",
            "status" => "open",
            "note" => nil,
            "created_at" => "2026-05-01T00:00:00Z",
            "last_updated_at" => "2026-05-01T00:00:00Z",
            "synced_at" => nil,
        }
        state = BootstrapStubState.new([{ repo: "jpr5/vulnerable-workflows-test", pr: existing_pr }])

        new_sentinel_pr = pulls_item(number: 5, state: "open", head_ref: "sentinel/security-fixes")
        new_sentinel_pr["html_url"] = "https://github.com/jpr5/vulnerable-workflows-test/pull/5"

        bootstrap = make_bootstrap(state: state) do |path|
            if path.include?("search/issues")
                { "total_count" => 0, "items" => [] }
            elsif path.include?("/repos/jpr5/vulnerable-workflows-test/pulls")
                [new_sentinel_pr]
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 1, result[:found]
        assert_equal 1, result[:new]
    end

    # -------------------------------------------------------
    # Test 8: Non-sentinel branches filtered out from pulls API
    # -------------------------------------------------------
    def test_filters_non_sentinel_branches
        existing_pr = {
            "url" => "https://github.com/jpr5/test-repo/pull/1",
            "number" => 1,
            "rule" => "unpinned-actions",
            "status" => "open",
            "note" => nil,
            "created_at" => "2026-05-01T00:00:00Z",
            "last_updated_at" => "2026-05-01T00:00:00Z",
            "synced_at" => nil,
        }
        state = BootstrapStubState.new([{ repo: "jpr5/test-repo", pr: existing_pr }])

        sentinel_pr = pulls_item(number: 10, head_ref: "sentinel/security-fixes")
        sentinel_pr["html_url"] = "https://github.com/jpr5/test-repo/pull/10"
        non_sentinel_pr = pulls_item(number: 11, head_ref: "feature/something-else")
        non_sentinel_pr["html_url"] = "https://github.com/jpr5/test-repo/pull/11"

        bootstrap = make_bootstrap(state: state) do |path|
            if path.include?("search/issues")
                { "total_count" => 0, "items" => [] }
            elsif path.include?("/repos/jpr5/test-repo/pulls")
                [sentinel_pr, non_sentinel_pr]
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 1, result[:found], "Should only find the sentinel/ branch PR"
        assert_equal 1, result[:new]
    end

    # -------------------------------------------------------
    # Test 9: Custom orgs parameter works
    # -------------------------------------------------------
    def test_custom_orgs_parameter
        state = BootstrapStubState.new

        pr = search_item(repo: "custom-org/repo", number: 1, state: "open")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:custom-org")
                { "total_count" => 1, "items" => [pr] }
            else
                { "total_count" => 0, "items" => [] }
            end
        end

        result = bootstrap.run(orgs: ["custom-org"])
        assert_equal 1, result[:found]
        assert_equal 1, result[:new]
    end

    # -------------------------------------------------------
    # Test 10: Repos in known orgs not double-checked via pulls API
    # -------------------------------------------------------
    def test_known_org_repos_not_double_checked
        existing_pr = {
            "url" => "https://github.com/CopilotKit/CopilotKit/pull/1",
            "number" => 1,
            "rule" => "unpinned-actions",
            "status" => "open",
            "note" => nil,
            "created_at" => "2026-05-01T00:00:00Z",
            "last_updated_at" => "2026-05-01T00:00:00Z",
            "synced_at" => nil,
        }
        state = BootstrapStubState.new([{ repo: "CopilotKit/CopilotKit", pr: existing_pr }])

        calls = []
        bootstrap = make_bootstrap(state: state) do |path|
            calls << path
            if path.include?("search/issues")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        bootstrap.run

        # Should NOT have called the pulls API for CopilotKit/CopilotKit
        pulls_calls = calls.select { |c| c.include?("/repos/CopilotKit/CopilotKit/pulls") }
        assert_empty pulls_calls, "Repos in known orgs should not be checked via pulls API"
    end

    # -------------------------------------------------------
    # Test 11: Uses "multiple" as rule for discovered PRs
    # -------------------------------------------------------
    def test_uses_multiple_as_rule
        state = BootstrapStubState.new

        pr = search_item(repo: "CopilotKit/CopilotKit", number: 42, state: "open")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 1, "items" => [pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        bootstrap.run

        assert_equal 1, state.recorded_prs.length
        assert_equal "multiple", state.recorded_prs.first[:rule]
    end

    # -------------------------------------------------------
    # Test 12: Stderr output is produced
    # -------------------------------------------------------
    def test_produces_stderr_output
        state = BootstrapStubState.new

        bootstrap = make_bootstrap(state: state) do |path|
            if path.include?("search/issues")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        output = capture_io { bootstrap.run }
        stderr = output[1]

        assert_includes stderr, "Bootstrapping PR tracker..."
        assert_includes stderr, "Searching CopilotKit org..."
        assert_includes stderr, "Searching ag-ui-protocol org..."
        assert_includes stderr, "Bootstrap complete:"
    end

    # -------------------------------------------------------
    # Test 13: Post-filter rejects non-Sentinel PRs from search results
    # -------------------------------------------------------
    def test_post_filter_rejects_non_sentinel_prs
        state = BootstrapStubState.new

        # A real Sentinel PR (has sentinel branch + body markers)
        sentinel_pr = search_item(
            repo: "CopilotKit/CopilotKit", number: 50, state: "open",
            title: "Security: Fix 3 findings in GitHub Actions workflows",
            body: "Automated fixes from Sentinel Bot\nhttps://sentinel.copilotkit.dev",
            head_ref: "sentinel/security-fixes",
        )

        # A non-Sentinel PR that happened to match the old broad search
        # (e.g. a manual CI hardening PR with "Security:" in the title)
        non_sentinel_pr = search_item(
            repo: "CopilotKit/CopilotKit", number: 99, state: "open",
            title: "Security: harden CI pipeline permissions",
            body: "Manual hardening of workflow permissions.",
            head_ref: "fix/ci-permissions",
        )

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 2, "items" => [sentinel_pr, non_sentinel_pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 1, result[:found], "Non-Sentinel PR should be filtered out"
        assert_equal 1, result[:new]
        assert_equal "CopilotKit/CopilotKit", state.recorded_prs.first[:repo]
        assert_equal 50, state.recorded_prs.first[:number]
    end

    # -------------------------------------------------------
    # Test 14: Post-filter accepts PRs matching different Sentinel signals
    # -------------------------------------------------------
    def test_post_filter_accepts_various_sentinel_signals
        state = BootstrapStubState.new

        # PR matched by head branch only
        by_branch = search_item(
            repo: "CopilotKit/CopilotKit", number: 10, state: "open",
            title: "Something unusual", body: "No sentinel keywords here.",
            head_ref: "sentinel/add-security-scan",
        )

        # PR matched by body containing sentinel.copilotkit.dev
        by_body_url = search_item(
            repo: "CopilotKit/CopilotKit", number: 20, state: "open",
            title: "Something else", body: "See https://sentinel.copilotkit.dev/report",
            head_ref: "some-other-branch",
        )

        # PR matched by title pattern
        by_title = search_item(
            repo: "CopilotKit/CopilotKit", number: 30, state: "open",
            title: "Security: Fix 5 findings in GitHub Actions workflows",
            body: "No other markers.", head_ref: "random-branch",
        )

        # PR matched by "Add Sentinel CI/CD" title
        by_adoption_title = search_item(
            repo: "CopilotKit/CopilotKit", number: 40, state: "open",
            title: "Add Sentinel CI/CD security scanning",
            body: "No other markers.", head_ref: "random-branch-2",
        )

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 4, "items" => [by_branch, by_body_url, by_title, by_adoption_title] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 4, result[:found], "All four Sentinel signal types should pass the filter"
        assert_equal 4, result[:new]
    end

    # -------------------------------------------------------
    # Test 15: Mixed scenario — some tracked, some new
    # -------------------------------------------------------
    def test_mixed_tracked_and_new
        existing_pr = {
            "url" => "https://github.com/CopilotKit/CopilotKit/pull/100",
            "number" => 100,
            "rule" => "unpinned-actions",
            "status" => "open",
            "note" => nil,
            "created_at" => "2026-05-01T00:00:00Z",
            "last_updated_at" => "2026-05-01T00:00:00Z",
            "synced_at" => nil,
        }
        state = BootstrapStubState.new([{ repo: "CopilotKit/CopilotKit", pr: existing_pr }])

        tracked = search_item(repo: "CopilotKit/CopilotKit", number: 100, state: "open")
        new_pr = search_item(repo: "CopilotKit/runtime", number: 200, state: "closed", merged_at: "2026-05-05T00:00:00Z")

        bootstrap = make_bootstrap(state: state) do |path|
            dp = URI.decode_www_form_component(path)
            if dp.include?("org:CopilotKit")
                { "total_count" => 2, "items" => [tracked, new_pr] }
            elsif dp.include?("org:ag-ui-protocol")
                { "total_count" => 0, "items" => [] }
            else
                nil
            end
        end

        result = bootstrap.run
        assert_equal 2, result[:found]
        assert_equal 1, result[:new]
        assert_equal 1, result[:already_tracked]
    end
end

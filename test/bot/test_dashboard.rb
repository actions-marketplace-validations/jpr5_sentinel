require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "time"

$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/scanner_bot"

class TestDashboard < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-dashboard-test")
        @state_file = File.join(@tmpdir, "state.json")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def build_state_with_prs
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/2", "rule-b", 2)
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/3", "rule-c", 3)
        state.record_pr("owner/repo4", "https://github.com/owner/repo4/pull/4", "rule-d", 4)

        state.update_pr_status("owner/repo1", 1, "blocked")
        state.update_pr_status("owner/repo2", 2, "open")
        state.update_pr_status("owner/repo3", 3, "merged")
        state.update_pr_status("owner/repo4", 4, "closed")
        state.save
        state
    end

    # --- Sort order tests ---

    def test_sort_order_blocked_open_merged_closed
        state = build_state_with_prs
        output = capture_io { print_dashboard(state) }[0]

        lines = output.lines.select { |l| l.match?(/owner\/repo/) }
        statuses = lines.map { |l| l[/blocked|open|merged|closed/] }

        assert_equal ["blocked", "open", "merged", "closed"], statuses,
            "Sort order should be blocked, open, merged, closed"
    end

    def test_status_sort_order_constant
        assert_equal 0, STATUS_SORT_ORDER["blocked"]
        assert_equal 1, STATUS_SORT_ORDER["open"]
        assert_equal 2, STATUS_SORT_ORDER["merged"]
        assert_equal 3, STATUS_SORT_ORDER["closed"]
    end

    # --- Exclusion tests ---

    def test_exclude_single_status
        state = build_state_with_prs
        output = capture_io { print_dashboard(state, excluded: ["closed"]) }[0]

        refute_match(/owner\/repo4/, output, "Closed PR should be excluded")
        assert_match(/owner\/repo1/, output, "Blocked PR should still show")
        assert_match(/owner\/repo2/, output, "Open PR should still show")
        assert_match(/owner\/repo3/, output, "Merged PR should still show")
    end

    def test_exclude_multiple_statuses
        state = build_state_with_prs
        output = capture_io { print_dashboard(state, excluded: ["closed", "merged"]) }[0]

        refute_match(/owner\/repo3/, output, "Merged PR should be excluded")
        refute_match(/owner\/repo4/, output, "Closed PR should be excluded")
        assert_match(/owner\/repo1/, output, "Blocked PR should still show")
        assert_match(/owner\/repo2/, output, "Open PR should still show")
    end

    def test_exclude_shows_header_indicator
        state = build_state_with_prs
        output = capture_io { print_dashboard(state, excluded: ["closed"]) }[0]

        assert_match(/excluding: closed/, output,
            "Header should indicate excluded statuses")
    end

    def test_exclude_multiple_shows_all_in_header
        state = build_state_with_prs
        output = capture_io { print_dashboard(state, excluded: ["closed", "merged"]) }[0]

        assert_match(/excluding: closed, merged/, output,
            "Header should show all excluded statuses")
    end

    # --- PR/Issue separation tests ---

    def test_dashboard_shows_pull_requests_section
        state = build_state_with_prs
        output = capture_io { print_dashboard(state) }[0]

        assert_match(/PULL REQUESTS/, output,
            "Dashboard should show PULL REQUESTS section header")
    end

    def test_dashboard_shows_issues_section
        state = build_state_with_prs
        output = capture_io { print_dashboard(state) }[0]

        assert_match(/ISSUES/, output,
            "Dashboard should show ISSUES section header")
    end

    def test_dashboard_separates_prs_and_issues
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/issues/2", "rule-b", 2, type: "issue")
        state.save

        output = capture_io { print_dashboard(state) }[0]

        # PR section should contain repo1 but not repo2
        pr_section = output.split("ISSUES")[0]
        assert_match(/owner\/repo1/, pr_section, "PR section should contain PR entries")

        # Issues section should contain repo2
        issue_section = output.split("ISSUES")[1]
        assert_match(/owner\/repo2/, issue_section, "Issues section should contain issue entries")
    end

    def test_dashboard_empty_issues_shows_no_tracked_issues
        state = build_state_with_prs  # only PRs
        output = capture_io { print_dashboard(state) }[0]

        assert_match(/No tracked issues/, output,
            "Should show 'No tracked issues.' when no issues exist")
    end

    def test_dashboard_empty_prs_shows_no_tracked_prs
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/issues/1", "rule-a", 1, type: "issue")
        state.save

        output = capture_io { print_dashboard(state) }[0]

        assert_match(/No tracked PRs\./, output,
            "Should show 'No tracked PRs.' when no PRs exist")
    end

    def test_dashboard_combined_summary
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/issues/2", "rule-b", 2, type: "issue")
        state.save

        output = capture_io { print_dashboard(state) }[0]

        assert_match(/PRs:.*1 open/, output, "Summary should show PR counts")
        assert_match(/Issues:.*1 open/, output, "Summary should show issue counts")
    end

    def test_dashboard_exclude_applies_to_both_sections
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.update_pr_status("owner/repo1", 1, "closed")
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/issues/2", "rule-b", 2, type: "issue")
        state.update_pr_status("owner/repo2", 2, "closed")
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/3", "rule-c", 3)
        state.save

        output = capture_io { print_dashboard(state, excluded: ["closed"]) }[0]

        refute_match(/owner\/repo1/, output, "Closed PR should be excluded")
        refute_match(/owner\/repo2/, output, "Closed issue should be excluded")
        assert_match(/owner\/repo3/, output, "Open PR should still show")
    end

    def test_no_exclusion_shows_all
        state = build_state_with_prs
        output = capture_io { print_dashboard(state) }[0]

        assert_match(/owner\/repo1/, output)
        assert_match(/owner\/repo2/, output)
        assert_match(/owner\/repo3/, output)
        assert_match(/owner\/repo4/, output)
    end

    def test_empty_exclusion_shows_all
        state = build_state_with_prs
        output = capture_io { print_dashboard(state, excluded: []) }[0]

        assert_match(/owner\/repo1/, output)
        assert_match(/owner\/repo2/, output)
        assert_match(/owner\/repo3/, output)
        assert_match(/owner\/repo4/, output)
    end

    def test_exclude_all_shows_empty_message
        state = build_state_with_prs
        output = capture_io {
            print_dashboard(state, excluded: ["blocked", "open", "merged", "closed"])
        }[0]

        assert_match(/No tracked PRs or issues after filtering/, output,
            "Should show empty message when all are excluded")
    end

    def test_empty_prs_shows_bootstrap_hint
        state = Bot::State.new(@state_file)
        output = capture_io { print_dashboard(state) }[0]

        assert_match(/No tracked PRs or issues/, output)
        assert_match(/--bootstrap/, output)
    end

    # --- Persistence integration ---

    def test_exclusion_persists_through_state
        state = Bot::State.new(@state_file)
        state.set_dashboard_excluded_statuses(["closed", "merged"])
        state.save

        reloaded = Bot::State.new(@state_file)
        assert_equal ["closed", "merged"], reloaded.dashboard_excluded_statuses
    end

    def test_exclusion_none_resets_preference
        state = Bot::State.new(@state_file)
        state.set_dashboard_excluded_statuses(["closed"])
        state.save

        reloaded = Bot::State.new(@state_file)
        reloaded.set_dashboard_excluded_statuses([])
        reloaded.save

        final = Bot::State.new(@state_file)
        assert_equal [], final.dashboard_excluded_statuses
    end
end

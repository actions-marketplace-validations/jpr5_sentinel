require_relative "test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "time"

# Load bot modules
require_relative "../bot/config"
require_relative "../bot/state"

class TestBotState < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-bot-test")
        @state_file = File.join(@tmpdir, "state.json")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def test_initialization_creates_empty_state
        state = Bot::State.new(@state_file)
        summary = state.summary
        assert_equal 0, summary[:total_repos]
        assert_equal 0, summary[:total_prs]
        assert_equal 0, summary[:prs_today]
        assert_equal 0, summary[:opt_outs]
    end

    def test_initialization_from_nonexistent_file
        nonexistent = File.join(@tmpdir, "does_not_exist.json")
        state = Bot::State.new(nonexistent)
        assert_equal 0, state.summary[:total_repos]
    end

    def test_initialization_from_existing_file
        data = {
            "repos" => {
                "owner/repo" => {
                    "scans" => [],
                    "prs" => [],
                    "last_scanned_at" => Time.now.utc.iso8601,
                    "status" => "scanned"
                }
            },
            "prs" => [],
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        assert_equal 1, state.summary[:total_repos]
    end

    def test_record_scan_stores_data
        state = Bot::State.new(@state_file)
        findings = [
            Finding.new(rule: "unpinned-actions", severity: :critical, file: "ci.yml", line: 1, code: "", message: "msg", fix: "fix"),
            Finding.new(rule: "shell-injection", severity: :high, file: "ci.yml", line: 5, code: "", message: "msg2", fix: "fix2"),
        ]

        state.record_scan("owner/repo", findings)

        assert_equal 1, state.summary[:total_repos]
    end

    def test_record_scan_stores_finding_count
        state = Bot::State.new(@state_file)
        findings = [
            Finding.new(rule: "rule-a", severity: :low, file: "ci.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "rule-b", severity: :low, file: "ci.yml", line: 2, code: "", message: "m", fix: "f"),
            Finding.new(rule: "rule-c", severity: :low, file: "ci.yml", line: 3, code: "", message: "m", fix: "f"),
        ]

        state.record_scan("owner/repo", findings)
        state.save

        # Reload and verify
        raw = JSON.parse(File.read(@state_file))
        scan_entry = raw["repos"]["owner/repo"]["scans"].last
        assert_equal 3, scan_entry["finding_count"]
    end

    def test_record_scan_stores_unique_rules
        state = Bot::State.new(@state_file)
        findings = [
            Finding.new(rule: "rule-a", severity: :low, file: "ci.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "rule-a", severity: :low, file: "ci.yml", line: 2, code: "", message: "m", fix: "f"),
            Finding.new(rule: "rule-b", severity: :low, file: "ci.yml", line: 3, code: "", message: "m", fix: "f"),
        ]

        state.record_scan("owner/repo", findings)
        state.save

        raw = JSON.parse(File.read(@state_file))
        scan_entry = raw["repos"]["owner/repo"]["scans"].last
        assert_equal ["rule-a", "rule-b"], scan_entry["rules"].sort
    end

    def test_record_pr_stores_pr_info
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions")

        assert_equal 1, state.summary[:total_prs]
    end

    def test_record_pr_stores_url_and_rule
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/42", "shell-injection")
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr_entry = raw["prs"].last
        assert_equal "owner/repo", pr_entry["repo"]
        assert_equal "https://github.com/owner/repo/pull/42", pr_entry["url"]
        assert_equal "shell-injection", pr_entry["rule"]
        refute_nil pr_entry["timestamp"]
    end

    def test_record_pr_also_stores_in_repo_prs
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "rule-a")
        state.save

        raw = JSON.parse(File.read(@state_file))
        repo_prs = raw["repos"]["owner/repo"]["prs"]
        assert_equal 1, repo_prs.length
        assert_equal "rule-a", repo_prs[0]["rule"]
    end

    def test_prs_opened_today_counts_correctly
        state = Bot::State.new(@state_file)

        # Record some PRs "today"
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a")
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/1", "rule-b")
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/1", "rule-c")

        assert_equal 3, state.prs_opened_today
    end

    def test_prs_opened_today_excludes_old_prs
        # Build state with an old PR
        old_timestamp = (Time.now.utc - 86400 * 2).iso8601
        data = {
            "repos" => {},
            "prs" => [
                { "repo" => "owner/old", "url" => "https://example.com/1", "rule" => "r", "timestamp" => old_timestamp }
            ],
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        assert_equal 0, state.prs_opened_today
    end

    def test_rate_limit_reached_respects_max_prs_per_day
        state = Bot::State.new(@state_file)

        # Record MAX_PRS_PER_DAY PRs
        Bot::Config::MAX_PRS_PER_DAY.times do |i|
            state.record_pr("owner/repo#{i}", "https://github.com/owner/repo#{i}/pull/1", "rule-a")
        end

        assert state.rate_limit_reached?, "Rate limit should be reached after #{Bot::Config::MAX_PRS_PER_DAY} PRs"
    end

    def test_rate_limit_not_reached_under_max
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a")

        refute state.rate_limit_reached?, "Rate limit should not be reached with only 1 PR"
    end

    def test_save_load_round_trip
        state = Bot::State.new(@state_file)
        state.record_scan("owner/repo", [
            Finding.new(rule: "test-rule", severity: :high, file: "ci.yml", line: 1, code: "", message: "m", fix: "f")
        ])
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "test-rule")
        state.record_opt_out("owner/opted-out")
        state.save

        # Load from same file
        loaded = Bot::State.new(@state_file)
        assert_equal 1, loaded.summary[:total_repos]
        assert_equal 1, loaded.summary[:total_prs]
        assert_equal 1, loaded.summary[:opt_outs]
        assert loaded.opted_out?("owner/opted-out")
    end

    def test_atomic_save_uses_tmp_file
        state = Bot::State.new(@state_file)
        state.record_scan("owner/repo", [])
        state.save

        # The final file should exist
        assert File.exist?(@state_file), "State file should exist after save"

        # The tmp file should NOT exist (it was renamed)
        refute File.exist?("#{@state_file}.tmp"), "Temp file should not remain after save"
    end

    def test_prune_removes_old_entries
        old_timestamp = (Time.now.utc - 91 * 86400).iso8601
        recent_timestamp = Time.now.utc.iso8601

        data = {
            "repos" => {
                "owner/old-repo" => {
                    "scans" => [],
                    "prs" => [],
                    "last_scanned_at" => old_timestamp,
                    "status" => "scanned"
                },
                "owner/recent-repo" => {
                    "scans" => [],
                    "prs" => [],
                    "last_scanned_at" => recent_timestamp,
                    "status" => "scanned"
                }
            },
            "prs" => [],
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save  # save triggers prune

        raw = JSON.parse(File.read(@state_file))
        refute raw["repos"].key?("owner/old-repo"), "Old repo should be pruned"
        assert raw["repos"].key?("owner/recent-repo"), "Recent repo should be kept"
    end

    def test_prune_keeps_repos_with_prs
        old_timestamp = (Time.now.utc - 91 * 86400).iso8601

        data = {
            "repos" => {
                "owner/old-with-pr" => {
                    "scans" => [],
                    "prs" => [{ "url" => "https://example.com/1", "rule" => "r", "timestamp" => old_timestamp }],
                    "last_scanned_at" => old_timestamp,
                    "status" => "pr_opened"
                }
            },
            "prs" => [],
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        # status is "pr_opened", not "scanned", so prune should keep it
        assert raw["repos"].key?("owner/old-with-pr"),
            "Repo with non-scanned status should survive prune"
    end

    def test_already_processed_returns_true_for_known_rule
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions")

        assert state.already_processed?("owner/repo", "unpinned-actions")
    end

    def test_already_processed_returns_false_for_unknown_rule
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions")

        refute state.already_processed?("owner/repo", "shell-injection")
    end

    def test_already_processed_returns_false_for_unknown_repo
        state = Bot::State.new(@state_file)
        refute state.already_processed?("owner/unknown", "unpinned-actions")
    end

    def test_opt_out_and_opted_out
        state = Bot::State.new(@state_file)
        refute state.opted_out?("owner/repo")

        state.record_opt_out("owner/repo")
        assert state.opted_out?("owner/repo")
    end

    def test_opt_out_is_idempotent
        state = Bot::State.new(@state_file)
        state.record_opt_out("owner/repo")
        state.record_opt_out("owner/repo")

        assert_equal 1, state.summary[:opt_outs]
    end

    def test_multiple_scans_for_same_repo
        state = Bot::State.new(@state_file)
        state.record_scan("owner/repo", [
            Finding.new(rule: "rule-a", severity: :low, file: "ci.yml", line: 1, code: "", message: "m", fix: "f"),
        ])
        state.record_scan("owner/repo", [
            Finding.new(rule: "rule-b", severity: :high, file: "ci.yml", line: 2, code: "", message: "m", fix: "f"),
        ])
        state.save

        raw = JSON.parse(File.read(@state_file))
        assert_equal 2, raw["repos"]["owner/repo"]["scans"].length
    end
end

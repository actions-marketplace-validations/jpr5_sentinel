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

    def test_initialization_default_has_no_top_level_prs
        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        refute raw.key?("prs"), "Default state should not have top-level prs array"
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

    # --- record_pr enriched entry tests ---

    def test_record_pr_stores_enriched_entry
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/42", "unpinned-actions", 42)
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr_entry = raw["repos"]["owner/repo"]["prs"].last

        assert_equal "https://github.com/owner/repo/pull/42", pr_entry["url"]
        assert_equal 42, pr_entry["number"]
        assert_equal "unpinned-actions", pr_entry["rule"]
        assert_equal "open", pr_entry["status"]
        assert_nil pr_entry["note"]
        refute_nil pr_entry["created_at"]
        refute_nil pr_entry["last_updated_at"]
        assert_nil pr_entry["synced_at"]
    end

    def test_record_pr_stores_pr_info
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions", 1)

        assert_equal 1, state.summary[:total_prs]
    end

    def test_record_pr_no_top_level_prs
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/42", "shell-injection", 42)
        state.save

        raw = JSON.parse(File.read(@state_file))
        refute raw.key?("prs"), "Should not have top-level prs array"
    end

    def test_record_pr_stores_in_repo_prs
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "rule-a", 1)
        state.save

        raw = JSON.parse(File.read(@state_file))
        repo_prs = raw["repos"]["owner/repo"]["prs"]
        assert_equal 1, repo_prs.length
        assert_equal "rule-a", repo_prs[0]["rule"]
        assert_equal 1, repo_prs[0]["number"]
    end

    # --- update_pr_status tests ---

    def test_update_pr_status_changes_status_and_last_updated_at
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/5", "rule-a", 5)

        # Small sleep to ensure timestamp difference
        sleep 0.01

        state.update_pr_status("owner/repo", 5, "merged")
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first
        assert_equal "merged", pr["status"]
        assert pr["last_updated_at"] >= pr["created_at"],
            "last_updated_at should be >= created_at after status update"
    end

    def test_update_pr_status_sets_note
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/10", "rule-a", 10)

        state.update_pr_status("owner/repo", 10, "closed", note: "Owner declined fix")
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first
        assert_equal "closed", pr["status"]
        assert_equal "Owner declined fix", pr["note"]
    end

    def test_update_pr_status_no_op_for_unknown_repo
        state = Bot::State.new(@state_file)
        # Should not raise
        state.update_pr_status("nonexistent/repo", 1, "merged")
    end

    def test_update_pr_status_no_op_for_unknown_pr_number
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/5", "rule-a", 5)
        # Should not raise
        state.update_pr_status("owner/repo", 999, "merged")

        state.save
        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first
        assert_equal "open", pr["status"], "PR status should not change when updating unknown number"
    end

    # --- prs_by_status tests ---

    def test_prs_by_status_filters_correctly
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/2", "rule-b", 2)
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/3", "rule-c", 3)

        state.update_pr_status("owner/repo2", 2, "merged")

        open_prs = state.prs_by_status("open")
        merged_prs = state.prs_by_status("merged")

        assert_equal 2, open_prs.length
        assert_equal 1, merged_prs.length
        assert_equal "owner/repo2", merged_prs.first[:repo]
    end

    def test_prs_by_status_returns_empty_for_no_matches
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "rule-a", 1)

        assert_equal [], state.prs_by_status("merged")
    end

    # --- all_tracked_prs tests ---

    def test_all_tracked_prs_returns_flat_list_with_repo_context
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/2", "rule-b", 2)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/3", "rule-c", 3)

        all = state.all_tracked_prs
        assert_equal 3, all.length

        repos = all.map { |entry| entry[:repo] }
        assert_includes repos, "owner/repo1"
        assert_includes repos, "owner/repo2"

        # Each entry has :repo and :pr keys
        all.each do |entry|
            assert entry.key?(:repo), "Each entry should have :repo key"
            assert entry.key?(:pr), "Each entry should have :pr key"
            assert entry[:pr].is_a?(Hash), "pr should be a Hash"
        end
    end

    def test_all_tracked_prs_empty_when_no_prs
        state = Bot::State.new(@state_file)
        assert_equal [], state.all_tracked_prs
    end

    # --- non_terminal_prs tests ---

    def test_non_terminal_prs_excludes_merged
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/2", "rule-b", 2)
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/3", "rule-c", 3)

        state.update_pr_status("owner/repo2", 2, "merged")

        non_terminal = state.non_terminal_prs
        assert_equal 2, non_terminal.length
        repos = non_terminal.map { |e| e[:repo] }
        refute_includes repos, "owner/repo2"
    end

    def test_non_terminal_prs_includes_closed
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.update_pr_status("owner/repo1", 1, "closed")

        non_terminal = state.non_terminal_prs
        assert_equal 1, non_terminal.length
        assert_equal "closed", non_terminal.first[:pr]["status"]
    end

    def test_non_terminal_prs_includes_open
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)

        non_terminal = state.non_terminal_prs
        assert_equal 1, non_terminal.length
        assert_equal "open", non_terminal.first[:pr]["status"]
    end

    # --- Migration tests ---

    def test_migration_removes_top_level_prs_array
        data = {
            "repos" => {
                "owner/repo" => {
                    "scans" => [],
                    "prs" => [
                        { "url" => "https://github.com/owner/repo/pull/1", "rule" => "rule-a", "timestamp" => "2025-01-01T00:00:00Z" }
                    ],
                }
            },
            "prs" => [
                { "repo" => "owner/repo", "url" => "https://github.com/owner/repo/pull/1", "rule" => "rule-a", "timestamp" => "2025-01-01T00:00:00Z" }
            ],
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        refute raw.key?("prs"), "Top-level prs array should be removed by migration"
    end

    def test_migration_backfills_number_from_url
        data = {
            "repos" => {
                "owner/repo" => {
                    "scans" => [],
                    "prs" => [
                        { "url" => "https://github.com/owner/repo/pull/42", "rule" => "rule-a", "timestamp" => "2025-01-01T00:00:00Z" }
                    ],
                }
            },
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first
        assert_equal 42, pr["number"]
    end

    def test_migration_backfills_status_and_timestamps
        ts = "2025-03-15T12:00:00Z"
        data = {
            "repos" => {
                "owner/repo" => {
                    "scans" => [],
                    "prs" => [
                        { "url" => "https://github.com/owner/repo/pull/7", "rule" => "rule-a", "timestamp" => ts }
                    ],
                }
            },
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first

        assert_equal "open", pr["status"]
        assert_nil pr["synced_at"]
        assert_nil pr["note"]
        assert_equal ts, pr["created_at"]
        assert_equal ts, pr["last_updated_at"]
    end

    def test_migration_does_not_overwrite_existing_fields
        data = {
            "repos" => {
                "owner/repo" => {
                    "scans" => [],
                    "prs" => [
                        {
                            "url" => "https://github.com/owner/repo/pull/10",
                            "number" => 10,
                            "rule" => "rule-a",
                            "status" => "merged",
                            "note" => "Merged successfully",
                            "created_at" => "2025-01-01T00:00:00Z",
                            "last_updated_at" => "2025-01-02T00:00:00Z",
                            "synced_at" => "2025-01-02T00:00:00Z",
                        }
                    ],
                }
            },
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        state.save

        raw = JSON.parse(File.read(@state_file))
        pr = raw["repos"]["owner/repo"]["prs"].first

        assert_equal 10, pr["number"]
        assert_equal "merged", pr["status"]
        assert_equal "Merged successfully", pr["note"]
        assert_equal "2025-01-01T00:00:00Z", pr["created_at"]
        assert_equal "2025-01-02T00:00:00Z", pr["last_updated_at"]
        assert_equal "2025-01-02T00:00:00Z", pr["synced_at"]
    end

    # --- prs_opened_today from repo-level data ---

    def test_prs_opened_today_counts_from_repo_level
        state = Bot::State.new(@state_file)

        # Record some PRs "today"
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/1", "rule-b", 1)
        state.record_pr("owner/repo3", "https://github.com/owner/repo3/pull/1", "rule-c", 1)

        assert_equal 3, state.prs_opened_today
    end

    def test_prs_opened_today_excludes_old_prs
        old_timestamp = (Time.now.utc - 86400 * 2).iso8601
        data = {
            "repos" => {
                "owner/old" => {
                    "scans" => [],
                    "prs" => [
                        { "url" => "https://github.com/owner/old/pull/1", "rule" => "r", "timestamp" => old_timestamp }
                    ],
                }
            },
            "opt_outs" => []
        }
        File.write(@state_file, JSON.pretty_generate(data))

        state = Bot::State.new(@state_file)
        assert_equal 0, state.prs_opened_today
    end

    # --- summary from repo-level data ---

    def test_summary_total_prs_from_repo_level
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/2", "rule-b", 2)
        state.record_pr("owner/repo2", "https://github.com/owner/repo2/pull/1", "rule-c", 1)

        summary = state.summary
        assert_equal 3, summary[:total_prs]
        assert_equal 2, summary[:total_repos]
    end

    # --- Rate limiting ---

    def test_rate_limit_reached_respects_max_prs_per_day
        state = Bot::State.new(@state_file)

        # Record MAX_PRS_PER_DAY PRs
        Bot::Config::MAX_PRS_PER_DAY.times do |i|
            state.record_pr("owner/repo#{i}", "https://github.com/owner/repo#{i}/pull/1", "rule-a", 1)
        end

        assert state.rate_limit_reached?, "Rate limit should be reached after #{Bot::Config::MAX_PRS_PER_DAY} PRs"
    end

    def test_rate_limit_not_reached_under_max
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo1", "https://github.com/owner/repo1/pull/1", "rule-a", 1)

        refute state.rate_limit_reached?, "Rate limit should not be reached with only 1 PR"
    end

    # --- Persistence ---

    def test_save_load_round_trip
        state = Bot::State.new(@state_file)
        state.record_scan("owner/repo", [
            Finding.new(rule: "test-rule", severity: :high, file: "ci.yml", line: 1, code: "", message: "m", fix: "f")
        ])
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "test-rule", 1)
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

    # --- Pruning ---

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
                    "prs" => [{ "url" => "https://github.com/owner/old-with-pr/pull/1", "rule" => "r", "timestamp" => old_timestamp }],
                    "last_scanned_at" => old_timestamp,
                    "status" => "pr_opened"
                }
            },
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

    # --- already_processed? ---

    def test_already_processed_returns_true_for_known_rule
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions", 1)

        assert state.already_processed?("owner/repo", "unpinned-actions")
    end

    def test_already_processed_returns_false_for_unknown_rule
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "unpinned-actions", 1)

        refute state.already_processed?("owner/repo", "shell-injection")
    end

    def test_already_processed_returns_false_for_unknown_repo
        state = Bot::State.new(@state_file)
        refute state.already_processed?("owner/unknown", "unpinned-actions")
    end

    # --- Opt out ---

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

    # --- Multiple scans ---

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

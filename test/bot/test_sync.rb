require "minitest/autorun"
require "json"
require "time"

require_relative "../../bot/config"
require_relative "../../bot/state"
require_relative "../../bot/sync"

# Stub State that tracks calls without needing a real file
class StubState
    attr_reader :updates

    def initialize(prs = [])
        @prs = prs  # Array of {repo:, pr: {hash}}
        @updates = []
    end

    def non_terminal_prs
        @prs.reject { |entry| entry[:pr]["status"] == "merged" }
    end

    def all_tracked_prs
        @prs
    end

    def update_pr_status(repo_name, number, status, note: nil, created_at: nil, updated_at: nil)
        @updates << { repo: repo_name, number: number, status: status, note: note, created_at: created_at, updated_at: updated_at }
        # Also update the in-memory PR so sync_all sees the change
        entry = @prs.find { |e| e[:repo] == repo_name && e[:pr]["number"] == number }
        if entry
            entry[:pr]["status"] = status
            entry[:pr]["note"] = note
            entry[:pr]["created_at"] = created_at if created_at
            entry[:pr]["last_updated_at"] = updated_at if updated_at
        end
    end
end

class TestBotSync < Minitest::Test
    def setup
        @token = "test-token"
    end

    # Helper: build a PR entry hash
    def make_pr(number:, status: "open", url: nil)
        url ||= "https://github.com/owner/repo/pull/#{number}"
        {
            "url" => url,
            "number" => number,
            "status" => status,
            "note" => nil,
            "created_at" => Time.now.utc.iso8601,
            "last_updated_at" => Time.now.utc.iso8601,
            "synced_at" => nil,
        }
    end

    # Helper: stub api_get responses on a Sync instance
    def stub_api(sync, responses = {})
        sync.define_singleton_method(:api_get) do |path|
            # Strip query params so stubs keyed by path-only still match
            base_path = path.split("?").first
            responses[path] || responses[base_path]
        end
    end

    # Helper: build a standard PR API response
    def pr_response(number:, state: "open", merged: false, head_sha: "abc123",
                    created_at: "2026-05-01T00:00:00Z", updated_at: "2026-05-10T00:00:00Z")
        {
            "number" => number,
            "state" => state,
            "merged" => merged,
            "head" => { "sha" => head_sha },
            "created_at" => created_at,
            "updated_at" => updated_at,
        }
    end

    # Helper: build a reviews API response
    def reviews_response(reviews = [])
        reviews.map do |r|
            {
                "user" => { "login" => r[:user] },
                "state" => r[:state],
            }
        end
    end

    # Helper: build a check-runs API response
    def check_runs_response(runs = [])
        {
            "check_runs" => runs.map do |r|
                {
                    "name" => r[:name],
                    "conclusion" => r[:conclusion],
                    "status" => r[:status] || "completed",
                }
            end,
        }
    end

    # -------------------------------------------------------
    # Test 1: PR that is merged → status becomes "merged"
    # -------------------------------------------------------
    def test_merged_pr
        pr = make_pr(number: 100)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/100" => pr_response(number: 100, state: "closed", merged: true),
            "/repos/owner/repo/pulls/100/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "merged", result
        assert_equal 1, state.updates.length
        assert_equal "merged", state.updates.first[:status]
        assert_nil state.updates.first[:note]
    end

    # -------------------------------------------------------
    # Test 2: PR that is closed (not merged) → "closed"
    # -------------------------------------------------------
    def test_closed_not_merged_pr
        pr = make_pr(number: 200)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/200" => pr_response(number: 200, state: "closed", merged: false),
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "closed", result
        assert_equal "closed", state.updates.first[:status]
    end

    # -------------------------------------------------------
    # Test 3: PR open with passing checks → stays "open"
    # -------------------------------------------------------
    def test_open_pr_with_passing_checks
        pr = make_pr(number: 300)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/300" => pr_response(number: 300),
            "/repos/owner/repo/pulls/300/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response([
                { name: "lint", conclusion: "success" },
                { name: "test", conclusion: "success" },
            ]),
            "/repos/owner/repo/pulls/300/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note]
    end

    # -------------------------------------------------------
    # Test 4: PR open with changes_requested → "blocked"
    # -------------------------------------------------------
    def test_open_pr_with_changes_requested
        pr = make_pr(number: 400)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/400" => pr_response(number: 400),
            "/repos/owner/repo/pulls/400/reviews" => reviews_response([
                { user: "AlemTuzlak", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/400/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        assert_equal "Changes requested by @AlemTuzlak", state.updates.first[:note]
    end

    # -------------------------------------------------------
    # Test 5: PR open with failing check-run → "blocked"
    # -------------------------------------------------------
    def test_open_pr_with_failing_ci
        pr = make_pr(number: 500)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/500" => pr_response(number: 500),
            "/repos/owner/repo/pulls/500/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response([
                { name: "lint", conclusion: "failure" },
                { name: "test", conclusion: "success" },
            ]),
            "/repos/owner/repo/pulls/500/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        assert_equal "CI failing: lint", state.updates.first[:note]
    end

    # -------------------------------------------------------
    # Test 6: CLA/DCO check failing → note mentions CLA/DCO
    # -------------------------------------------------------
    def test_cla_dco_check_failing
        pr = make_pr(number: 600)
        state = StubState.new([{ repo: "cncf/toc", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/cncf/toc/pulls/600" => pr_response(number: 600),
            "/repos/cncf/toc/pulls/600/reviews" => reviews_response,
            "/repos/cncf/toc/commits/abc123/check-runs" => check_runs_response([
                { name: "DCO", conclusion: "failure" },
                { name: "test", conclusion: "success" },
            ]),
            "/repos/cncf/toc/pulls/600/comments" => [],
        })

        result = sync.sync_pr("cncf/toc", pr)
        assert_equal "blocked", result
        assert_includes state.updates.first[:note], "CLA/DCO check failing"
    end

    # -------------------------------------------------------
    # Test 7: Multiple blockers combine in note
    # -------------------------------------------------------
    def test_multiple_blockers_combined
        pr = make_pr(number: 700)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/700" => pr_response(number: 700),
            "/repos/owner/repo/pulls/700/reviews" => reviews_response([
                { user: "reviewer1", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response([
                { name: "lint", conclusion: "failure" },
            ]),
            "/repos/owner/repo/pulls/700/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result

        note = state.updates.first[:note]
        assert_includes note, "Changes requested by @reviewer1"
        assert_includes note, "CI failing: lint"
        # Joined with "; "
        assert_includes note, "; "
    end

    # -------------------------------------------------------
    # Test 8: API error (nil response) handled gracefully
    # -------------------------------------------------------
    def test_api_error_returns_nil
        pr = make_pr(number: 800)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/800" => nil,  # API returned 404/error
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_nil result
        assert_empty state.updates
    end

    # -------------------------------------------------------
    # Test 9: Merged PRs skipped unless force: true
    # -------------------------------------------------------
    def test_merged_prs_skipped_in_normal_sync
        pr_merged = make_pr(number: 900, status: "merged")
        pr_open = make_pr(number: 901, status: "open")
        state = StubState.new([
            { repo: "owner/repo", pr: pr_merged },
            { repo: "owner/repo", pr: pr_open },
        ])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/901" => pr_response(number: 901),
            "/repos/owner/repo/pulls/901/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/901/comments" => [],
        })

        results = sync.sync_all
        # Only the open PR should be synced (non_terminal_prs excludes merged)
        assert_equal 1, results[:synced]
    end

    def test_merged_prs_included_with_force
        pr_merged = make_pr(number: 900, status: "merged")
        pr_open = make_pr(number: 901, status: "open")
        state = StubState.new([
            { repo: "owner/repo", pr: pr_merged },
            { repo: "owner/repo", pr: pr_open },
        ])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/900" => pr_response(number: 900, state: "closed", merged: true, head_sha: "sha900"),
            "/repos/owner/repo/pulls/900/reviews" => reviews_response,
            "/repos/owner/repo/commits/sha900/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/901" => pr_response(number: 901, head_sha: "sha901"),
            "/repos/owner/repo/pulls/901/reviews" => reviews_response,
            "/repos/owner/repo/commits/sha901/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/901/comments" => [],
        })

        results = sync.sync_all(force: true)
        # Both PRs should be synced
        assert_equal 2, results[:synced]
    end

    # -------------------------------------------------------
    # Additional edge cases
    # -------------------------------------------------------

    def test_review_approved_after_changes_requested_is_not_blocked
        pr = make_pr(number: 1000)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1000" => pr_response(number: 1000),
            "/repos/owner/repo/pulls/1000/reviews" => reviews_response([
                { user: "reviewer1", state: "CHANGES_REQUESTED" },
                { user: "reviewer1", state: "APPROVED" },  # Later approval supersedes
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1000/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note]
    end

    def test_closed_pr_reopened_transitions_back
        pr = make_pr(number: 1100, status: "closed")
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1100" => pr_response(number: 1100, state: "open"),
            "/repos/owner/repo/pulls/1100/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1100/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
    end

    def test_nil_pr_number_returns_nil
        pr = make_pr(number: nil)
        pr.delete("number")
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        result = sync.sync_pr("owner/repo", pr)
        assert_nil result
    end

    def test_bad_repo_format_returns_nil
        pr = make_pr(number: 1200)
        state = StubState.new([{ repo: "badrepo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        result = sync.sync_pr("badrepo", pr)
        assert_nil result
    end

    def test_sync_all_counts_errors
        pr = make_pr(number: 1300)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1300" => nil,  # API error
        })

        results = sync.sync_all
        assert_equal 0, results[:synced]
        assert_equal 1, results[:errors]
    end

    def test_cla_check_case_insensitive
        pr = make_pr(number: 1400)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1400" => pr_response(number: 1400),
            "/repos/owner/repo/pulls/1400/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response([
                { name: "CLA Check", conclusion: "failure" },
            ]),
            "/repos/owner/repo/pulls/1400/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        assert_includes state.updates.first[:note], "CLA/DCO check failing"
    end

    def test_reviews_api_returns_nil_gracefully
        pr = make_pr(number: 1500)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1500" => pr_response(number: 1500),
            "/repos/owner/repo/pulls/1500/reviews" => nil,  # API error
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1500/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
    end

    def test_check_runs_api_returns_nil_gracefully
        pr = make_pr(number: 1600)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1600" => pr_response(number: 1600),
            "/repos/owner/repo/pulls/1600/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => nil,  # API error
            "/repos/owner/repo/pulls/1600/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
    end

    # -------------------------------------------------------
    # Test: sync_pr passes real GitHub timestamps to state
    # -------------------------------------------------------
    def test_sync_pr_passes_real_timestamps
        pr = make_pr(number: 1700)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1700" => pr_response(
                number: 1700,
                created_at: "2026-05-01T12:00:00Z",
                updated_at: "2026-05-15T18:30:00Z",
            ),
            "/repos/owner/repo/pulls/1700/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1700/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result

        update = state.updates.first
        assert_equal "2026-05-01T12:00:00Z", update[:created_at]
        assert_equal "2026-05-15T18:30:00Z", update[:updated_at]
    end

    # -------------------------------------------------------
    # Bot reviewer detection tests
    # -------------------------------------------------------

    def test_bot_reviewer_detects_bot_suffix
        sync = Bot::Sync.new(token: @token, state: StubState.new)
        assert sync.send(:bot_reviewer?, "codex[bot]"), "Should detect [bot] suffix"
        assert sync.send(:bot_reviewer?, "some-new-bot[bot]"), "Should detect arbitrary [bot] suffix"
        assert sync.send(:bot_reviewer?, "Codex[bot]"), "Should be case-insensitive"
    end

    def test_bot_reviewer_detects_known_accounts
        sync = Bot::Sync.new(token: @token, state: StubState.new)
        assert sync.send(:bot_reviewer?, "github-actions[bot]"), "Should detect github-actions[bot]"
        assert sync.send(:bot_reviewer?, "dependabot[bot]"), "Should detect dependabot[bot]"
        assert sync.send(:bot_reviewer?, "snyk-bot"), "Should detect snyk-bot"
        assert sync.send(:bot_reviewer?, "renovate[bot]"), "Should detect renovate[bot]"
        assert sync.send(:bot_reviewer?, "copilot[bot]"), "Should detect copilot[bot]"
    end

    def test_bot_reviewer_rejects_human_users
        sync = Bot::Sync.new(token: @token, state: StubState.new)
        refute sync.send(:bot_reviewer?, "AlemTuzlak"), "Human reviewer should not be detected as bot"
        refute sync.send(:bot_reviewer?, "jpr5"), "Human reviewer should not be detected as bot"
        refute sync.send(:bot_reviewer?, "octocat"), "Human reviewer should not be detected as bot"
    end

    def test_bot_reviewer_handles_nil_and_empty
        sync = Bot::Sync.new(token: @token, state: StubState.new)
        refute sync.send(:bot_reviewer?, nil), "nil should not be detected as bot"
        refute sync.send(:bot_reviewer?, ""), "empty string should not be detected as bot"
    end

    # -------------------------------------------------------
    # Bot review filtering in status derivation
    # -------------------------------------------------------

    def test_bot_changes_requested_does_not_block
        pr = make_pr(number: 1800)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1800" => pr_response(number: 1800),
            "/repos/owner/repo/pulls/1800/reviews" => reviews_response([
                { user: "codex[bot]", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1800/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note], "Bot CHANGES_REQUESTED should not produce a blocker note"
    end

    def test_codex_bot_changes_requested_ignored_while_human_blocks
        pr = make_pr(number: 1801)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1801" => pr_response(number: 1801),
            "/repos/owner/repo/pulls/1801/reviews" => reviews_response([
                { user: "codex[bot]", state: "CHANGES_REQUESTED" },
                { user: "real-reviewer", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1801/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        note = state.updates.first[:note]
        assert_includes note, "Changes requested by @real-reviewer"
        refute_includes note, "codex[bot]", "Bot review should not appear in blockers"
    end

    def test_multiple_bot_reviews_all_filtered
        pr = make_pr(number: 1802)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1802" => pr_response(number: 1802),
            "/repos/owner/repo/pulls/1802/reviews" => reviews_response([
                { user: "codex[bot]", state: "CHANGES_REQUESTED" },
                { user: "github-actions[bot]", state: "CHANGES_REQUESTED" },
                { user: "dependabot[bot]", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1802/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        # No human blockers, so no blocker note
    end

    def test_bot_approved_review_also_filtered
        pr = make_pr(number: 1803)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        # Bot approves, then human requests changes — only human matters
        stub_api(sync, {
            "/repos/owner/repo/pulls/1803" => pr_response(number: 1803),
            "/repos/owner/repo/pulls/1803/reviews" => reviews_response([
                { user: "codex[bot]", state: "APPROVED" },
                { user: "real-reviewer", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1803/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        assert_includes state.updates.first[:note], "Changes requested by @real-reviewer"
    end

    # -------------------------------------------------------
    # Bot review comment detection
    # -------------------------------------------------------

    def test_bot_review_comments_noted_but_dont_block
        pr = make_pr(number: 1900)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1900" => pr_response(number: 1900),
            "/repos/owner/repo/pulls/1900/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1900/comments" => [
                { "user" => { "login" => "codex[bot]" }, "body" => "This looks wrong" },
                { "user" => { "login" => "codex[bot]" }, "body" => "Another suggestion" },
            ],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result, "Bot review comments should not block"
        note = state.updates.first[:note]
        assert_includes note, "2 bot review comments from @codex[bot] (ignored)"
    end

    def test_single_bot_review_comment_singular_form
        pr = make_pr(number: 1901)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1901" => pr_response(number: 1901),
            "/repos/owner/repo/pulls/1901/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1901/comments" => [
                { "user" => { "login" => "copilot[bot]" }, "body" => "Suggestion here" },
            ],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        note = state.updates.first[:note]
        assert_includes note, "1 bot review comment from @copilot[bot] (ignored)"
    end

    def test_multiple_different_bots_each_noted
        pr = make_pr(number: 1902)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1902" => pr_response(number: 1902),
            "/repos/owner/repo/pulls/1902/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1902/comments" => [
                { "user" => { "login" => "codex[bot]" }, "body" => "Issue 1" },
                { "user" => { "login" => "copilot[bot]" }, "body" => "Issue 2" },
                { "user" => { "login" => "codex[bot]" }, "body" => "Issue 3" },
            ],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        note = state.updates.first[:note]
        assert_includes note, "codex[bot]"
        assert_includes note, "copilot[bot]"
    end

    def test_human_review_comments_not_flagged
        pr = make_pr(number: 1903)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1903" => pr_response(number: 1903),
            "/repos/owner/repo/pulls/1903/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1903/comments" => [
                { "user" => { "login" => "real-human" }, "body" => "Good work!" },
            ],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note], "Human comments should not generate notes"
    end

    def test_no_review_comments_clean_open
        pr = make_pr(number: 1904)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1904" => pr_response(number: 1904),
            "/repos/owner/repo/pulls/1904/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1904/comments" => [],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note]
    end

    def test_bot_comments_and_real_blocker_combined_in_note
        pr = make_pr(number: 1905)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1905" => pr_response(number: 1905),
            "/repos/owner/repo/pulls/1905/reviews" => reviews_response([
                { user: "real-maintainer", state: "CHANGES_REQUESTED" },
            ]),
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1905/comments" => [
                { "user" => { "login" => "codex[bot]" }, "body" => "False positive" },
            ],
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "blocked", result
        note = state.updates.first[:note]
        assert_includes note, "Changes requested by @real-maintainer"
        assert_includes note, "1 bot review comment from @codex[bot] (ignored)"
    end

    def test_comments_api_nil_handled_gracefully
        pr = make_pr(number: 1906)
        state = StubState.new([{ repo: "owner/repo", pr: pr }])
        sync = Bot::Sync.new(token: @token, state: state)

        stub_api(sync, {
            "/repos/owner/repo/pulls/1906" => pr_response(number: 1906),
            "/repos/owner/repo/pulls/1906/reviews" => reviews_response,
            "/repos/owner/repo/commits/abc123/check-runs" => check_runs_response,
            "/repos/owner/repo/pulls/1906/comments" => nil,
        })

        result = sync.sync_pr("owner/repo", pr)
        assert_equal "open", result
        assert_nil state.updates.first[:note]
    end
end

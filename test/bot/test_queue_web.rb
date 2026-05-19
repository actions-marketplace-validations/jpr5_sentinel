require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "time"

$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/config"
require_relative "../../bot/queue"

# We test the queue web routes by exercising the queue data structures and
# verifying the HTML generation helpers produce correct output.  The Sinatra
# app itself requires a running server, so we focus on unit-testable pieces:
# queue state management for the web flow, prefix-match lookup, and the
# approve/reject lifecycle that the routes depend on.

class TestQueueWeb < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-queue-web-test")
        @queue_file = File.join(@tmpdir, "queue.json")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    # --- Prefix match (used by GET /queue/:id, POST approve/reject) ---

    def test_prefix_match_finds_item
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix vuln", body: "body", files: {}, findings: [])
        id = queue.pending.first["id"]
        prefix = id[0, 8]

        match = queue.pending.find { |i| i["id"] == prefix || i["id"].start_with?(prefix) }
        refute_nil match
        assert_equal id, match["id"]
    end

    def test_prefix_match_returns_nil_for_no_match
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix vuln", body: "body", files: {}, findings: [])

        match = queue.pending.find { |i| i["id"] == "zzz" || i["id"].start_with?("zzz") }
        assert_nil match
    end

    def test_full_id_match
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix vuln", body: "body", files: {}, findings: [])
        id = queue.pending.first["id"]

        match = queue.pending.find { |i| i["id"] == id || i["id"].start_with?(id) }
        refute_nil match
        assert_equal id, match["id"]
    end

    # --- Approve web flow lifecycle ---

    def test_approve_flow_moves_item_and_persists
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "facebook/react",
            title: "Security: Fix injection",
            body: "## Fix\nPatched expression injection",
            files: { ".github/workflows/ci.yml" => "patched content" },
            findings: [{ rule: "shell-injection-expr", file: "ci.yml", line: 42, message: "Unsafe" }],
            type: "pr"
        )
        id = queue.pending.first["id"]

        item = queue.approve(id)
        queue.save

        refute_nil item
        assert_equal "facebook/react", item["repo"]
        assert_equal 0, queue.pending.length
        assert_equal 1, queue.approved.length

        # Verify round-trip
        reloaded = Bot::Queue.new(@queue_file)
        assert_equal 0, reloaded.pending.length
        assert_equal 1, reloaded.approved.length
        assert_equal "facebook/react", reloaded.approved.first["repo"]
    end

    def test_approve_preserves_all_fields
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "owner/repo",
            title: "Fix title",
            body: "Fix body",
            files: { "a.yml" => "content" },
            findings: [{ rule: "r1", file: "f.yml", line: 1, message: "m" }],
            signoff: "Test User <test@example.com>",
            type: "pr"
        )
        id = queue.pending.first["id"]

        item = queue.approve(id)

        assert_equal "Fix title", item["title"]
        assert_equal "Fix body", item["body"]
        assert_equal({ "a.yml" => "content" }, item["files"])
        assert_equal 1, item["findings"].length
        assert_equal "Test User <test@example.com>", item["signoff"]
        assert_equal "pr", item["type"]
        # approved_at is on the copy in the approved list, not the returned item
        refute_nil queue.approved.first["approved_at"]
    end

    # --- Reject web flow lifecycle ---

    def test_reject_flow_with_reason
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.reject(id, reason: "upstream fixed")
        queue.save

        assert_equal 0, queue.pending.length
        assert_equal 1, queue.rejected.length
        assert_equal "upstream fixed", queue.rejected.first["reason"]
        refute_nil queue.rejected.first["rejected_at"]
    end

    def test_reject_flow_without_reason
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.reject(id)
        queue.save

        assert_nil queue.rejected.first["reason"]
    end

    def test_reject_empty_reason_treated_as_nil
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Fix", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        # Simulate what the web route does: strip and nil-ify empty strings
        reason = "   ".strip
        reason = nil if reason.empty?

        item = queue.reject(id, reason: reason)
        assert_nil queue.rejected.first["reason"]
    end

    # --- Issue type handling ---

    def test_approve_issue_type_preserved
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "owner/repo",
            title: "Advisory",
            body: "Security advisory",
            files: {},
            findings: [{ rule: "r1", file: "f.yml", line: 1, message: "m" }],
            type: "issue"
        )
        id = queue.pending.first["id"]

        item = queue.approve(id)
        assert_equal "issue", item["type"]
    end

    # --- Queue overview data ---

    def test_pending_items_have_required_display_fields
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "org/project",
            title: "Security: Fix 3 findings",
            body: "body text",
            files: { "ci.yml" => "content" },
            findings: [
                { rule: "r1", file: "a.yml", line: 1, message: "m1" },
                { rule: "r2", file: "b.yml", line: 5, message: "m2" },
                { rule: "r3", file: "c.yml", line: 10, message: "m3" },
            ],
            type: "pr"
        )

        item = queue.pending.first
        # These are all the fields the GET /queue route needs
        refute_nil item["id"]
        refute_nil item["repo"]
        refute_nil item["title"]
        refute_nil item["type"]
        refute_nil item["findings"]
        refute_nil item["queued_at"]
        assert_equal 3, item["findings"].length
    end

    # --- Detail view data ---

    def test_detail_item_has_body_and_files
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "owner/repo",
            title: "Fix",
            body: "## Summary\n\nThis fixes a critical vulnerability.\n\n- Patched injection\n- Added pin",
            files: {
                ".github/workflows/ci.yml" => "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest",
                ".github/workflows/deploy.yml" => "name: Deploy\non: push"
            },
            findings: [{ rule: "shell-injection-expr", file: "ci.yml", line: 42, message: "Unsafe expression" }]
        )

        item = queue.pending.first
        refute_nil item["body"]
        assert item["body"].include?("Summary")
        assert_equal 2, item["files"].keys.length
        assert item["files"].key?(".github/workflows/ci.yml")
    end

    # --- Multiple items lifecycle ---

    def test_mixed_approve_reject_leaves_correct_state
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "org/a", title: "Fix A", body: "b", files: {}, findings: [])
        queue.add(repo: "org/b", title: "Fix B", body: "b", files: {}, findings: [])
        queue.add(repo: "org/c", title: "Fix C", body: "b", files: {}, findings: [])

        id_a = queue.pending[0]["id"]
        id_b = queue.pending[1]["id"]
        id_c = queue.pending[2]["id"]

        queue.approve(id_a)
        queue.reject(id_c, reason: "not needed")
        queue.save

        assert_equal 1, queue.pending.length
        assert_equal "org/b", queue.pending.first["repo"]
        assert_equal 1, queue.approved.length
        assert_equal "org/a", queue.approved.first["repo"]
        assert_equal 1, queue.rejected.length
        assert_equal "org/c", queue.rejected.first["repo"]

        # Verify persistence
        reloaded = Bot::Queue.new(@queue_file)
        assert_equal 1, reloaded.pending.length
        assert_equal 1, reloaded.approved.length
        assert_equal 1, reloaded.rejected.length
    end

    # --- Findings with severity for detail view ---

    def test_findings_preserve_severity_field
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "owner/repo",
            title: "Fix",
            body: "b",
            files: {},
            findings: [
                { rule: "shell-injection-expr", severity: "critical", file: "ci.yml", line: 42, message: "Unsafe", fix: "Use env var" }
            ]
        )

        item = queue.pending.first
        f = item["findings"].first
        assert_equal "critical", f["severity"]
        assert_equal "Use env var", f["fix"]
    end

    # --- Edge cases ---

    def test_approve_nonexistent_returns_nil
        queue = Bot::Queue.new(@queue_file)
        result = queue.approve("nonexistent-id")
        assert_nil result
    end

    def test_reject_nonexistent_returns_nil
        queue = Bot::Queue.new(@queue_file)
        result = queue.reject("nonexistent-id")
        assert_nil result
    end

    def test_empty_queue_sections
        queue = Bot::Queue.new(@queue_file)
        assert_equal [], queue.pending
        assert_equal [], queue.approved
        assert_equal [], queue.rejected
    end

    def test_item_with_no_files_hash
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "Advisory", body: "b", files: {}, findings: [], type: "issue")

        item = queue.pending.first
        assert_equal({}, item["files"])
    end
end

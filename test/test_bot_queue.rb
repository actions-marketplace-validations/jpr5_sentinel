require_relative "test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "time"

# Load bot modules
require_relative "../bot/config"
require_relative "../bot/queue"

class TestBotQueue < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-queue-test")
        @queue_file = File.join(@tmpdir, "queue.json")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def test_initialization_creates_empty_queue
        queue = Bot::Queue.new(@queue_file)
        assert_equal [], queue.pending
        assert_equal [], queue.approved
        assert_equal [], queue.rejected
        assert_equal 0, queue.size
    end

    def test_initialization_from_nonexistent_file
        nonexistent = File.join(@tmpdir, "does_not_exist.json")
        queue = Bot::Queue.new(nonexistent)
        assert_equal 0, queue.size
    end

    def test_initialization_from_existing_file
        data = {
            "pending" => [
                { "id" => "abc-123", "repo" => "owner/repo", "title" => "Fix 1", "body" => "body",
                  "files" => {}, "findings" => [], "queued_at" => Time.now.utc.iso8601 }
            ],
            "approved" => [],
            "rejected" => []
        }
        File.write(@queue_file, JSON.pretty_generate(data))

        queue = Bot::Queue.new(@queue_file)
        assert_equal 1, queue.size
    end

    def test_add_creates_pending_item
        queue = Bot::Queue.new(@queue_file)

        findings = [
            Finding.new(rule: "shell-injection-expr", severity: :critical, file: "ci.yml", line: 42, code: "", message: "Unsafe expression", fix: "fix"),
        ]

        queue.add(
            repo: "facebook/react",
            title: "Security: Fix 1 finding",
            body: "PR body here",
            files: { ".github/workflows/ci.yml" => "patched content" },
            findings: findings,
            signoff: nil
        )

        assert_equal 1, queue.size
        item = queue.pending.first
        assert_equal "facebook/react", item["repo"]
        assert_equal "Security: Fix 1 finding", item["title"]
        assert_equal "PR body here", item["body"]
        assert_equal({ ".github/workflows/ci.yml" => "patched content" }, item["files"])
        assert_nil item["signoff"]
        refute_nil item["id"]
        refute_nil item["queued_at"]
    end

    def test_add_serializes_finding_objects
        queue = Bot::Queue.new(@queue_file)

        findings = [
            Finding.new(rule: "shell-injection-expr", severity: :critical, file: "ci.yml", line: 292, code: "", message: "Unsafe expr", fix: "fix"),
            Finding.new(rule: "shell-injection-expr", severity: :critical, file: "ci.yml", line: 466, code: "", message: "Another expr", fix: "fix2"),
        ]

        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: findings)

        item = queue.pending.first
        assert_equal 2, item["findings"].length
        assert_equal "shell-injection-expr", item["findings"][0]["rule"]
        assert_equal "ci.yml", item["findings"][0]["file"]
        assert_equal 292, item["findings"][0]["line"]
        assert_equal "Unsafe expr", item["findings"][0]["message"]
    end

    def test_add_accepts_hash_findings
        queue = Bot::Queue.new(@queue_file)

        findings = [
            { rule: "test-rule", file: "ci.yml", line: 10, message: "test msg" }
        ]

        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: findings)

        item = queue.pending.first
        assert_equal "test-rule", item["findings"][0]["rule"]
    end

    def test_add_stores_signoff
        queue = Bot::Queue.new(@queue_file)
        queue.add(
            repo: "owner/repo",
            title: "t",
            body: "b",
            files: {},
            findings: [],
            signoff: "Jordan Ritter <jpr5@darkridge.com>"
        )

        item = queue.pending.first
        assert_equal "Jordan Ritter <jpr5@darkridge.com>", item["signoff"]
    end

    def test_approve_moves_item_from_pending_to_approved
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.approve(id)

        refute_nil item
        assert_equal 0, queue.pending.length
        assert_equal 1, queue.approved.length
        assert_equal id, queue.approved.first["id"]
        refute_nil queue.approved.first["approved_at"]
    end

    def test_approve_returns_nil_for_unknown_id
        queue = Bot::Queue.new(@queue_file)
        result = queue.approve("nonexistent-id")
        assert_nil result
    end

    def test_reject_moves_item_from_pending_to_rejected
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.reject(id, reason: "upstream already fixed")

        refute_nil item
        assert_equal 0, queue.pending.length
        assert_equal 1, queue.rejected.length
        assert_equal id, queue.rejected.first["id"]
        assert_equal "upstream already fixed", queue.rejected.first["reason"]
        refute_nil queue.rejected.first["rejected_at"]
    end

    def test_reject_without_reason
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.reject(id)

        assert_nil queue.rejected.first["reason"]
    end

    def test_reject_returns_nil_for_unknown_id
        queue = Bot::Queue.new(@queue_file)
        result = queue.reject("nonexistent-id")
        assert_nil result
    end

    def test_find_returns_pending_item
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        id = queue.pending.first["id"]

        item = queue.find(id)
        refute_nil item
        assert_equal id, item["id"]
    end

    def test_find_returns_nil_for_unknown_id
        queue = Bot::Queue.new(@queue_file)
        assert_nil queue.find("nonexistent")
    end

    def test_save_and_reload_round_trip
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo1", title: "PR 1", body: "b", files: {}, findings: [])
        queue.add(repo: "owner/repo2", title: "PR 2", body: "b", files: {}, findings: [])

        id1 = queue.pending[0]["id"]
        queue.approve(id1)
        queue.save

        # Reload from disk
        reloaded = Bot::Queue.new(@queue_file)
        assert_equal 1, reloaded.pending.length
        assert_equal 1, reloaded.approved.length
        assert_equal "owner/repo2", reloaded.pending.first["repo"]
        assert_equal "owner/repo1", reloaded.approved.first["repo"]
    end

    def test_atomic_save_no_tmp_file_left
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        queue.save

        assert File.exist?(@queue_file), "Queue file should exist after save"
        refute File.exist?("#{@queue_file}.tmp"), "Temp file should not remain after save"
    end

    def test_multiple_items_independent_lifecycle
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo1", title: "t1", body: "b", files: {}, findings: [])
        queue.add(repo: "owner/repo2", title: "t2", body: "b", files: {}, findings: [])
        queue.add(repo: "owner/repo3", title: "t3", body: "b", files: {}, findings: [])

        id1 = queue.pending[0]["id"]
        id2 = queue.pending[1]["id"]
        id3 = queue.pending[2]["id"]

        queue.approve(id1)
        queue.reject(id3, reason: "not needed")

        assert_equal 1, queue.pending.length
        assert_equal id2, queue.pending.first["id"]
        assert_equal 1, queue.approved.length
        assert_equal 1, queue.rejected.length
    end

    def test_size_tracks_pending_count
        queue = Bot::Queue.new(@queue_file)
        assert_equal 0, queue.size

        queue.add(repo: "owner/repo1", title: "t", body: "b", files: {}, findings: [])
        assert_equal 1, queue.size

        queue.add(repo: "owner/repo2", title: "t", body: "b", files: {}, findings: [])
        assert_equal 2, queue.size

        id = queue.pending.first["id"]
        queue.approve(id)
        assert_equal 1, queue.size
    end

    def test_env_var_queue_path
        custom_path = File.join(@tmpdir, "custom_queue.json")
        ENV["SENTINEL_QUEUE_PATH"] = custom_path

        queue = Bot::Queue.new
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        queue.save

        assert File.exist?(custom_path)
    ensure
        ENV.delete("SENTINEL_QUEUE_PATH")
    end

    def test_unique_ids_for_each_item
        queue = Bot::Queue.new(@queue_file)
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])
        queue.add(repo: "owner/repo", title: "t", body: "b", files: {}, findings: [])

        ids = queue.pending.map { |i| i["id"] }
        assert_equal ids.uniq, ids, "Each queue item should have a unique ID"
    end
end

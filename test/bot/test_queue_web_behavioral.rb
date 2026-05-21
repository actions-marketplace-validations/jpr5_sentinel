require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "time"
require "rack/test"

# Set test environment before loading the app
ENV["RACK_ENV"] = "test"

$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))

require_relative "../../bot/config"
require_relative "../../bot/queue"
require_relative "../../bot/state"

# Load web.rb which defines routes on Sinatra::Application
require_relative "../../bot/web"

class TestQueueWebBehavioral < Minitest::Test
    include Rack::Test::Methods

    def app
        Sinatra::Application
    end

    def setup
        @tmpdir = Dir.mktmpdir("sentinel-queue-web-behavioral")
        @queue_file = File.join(@tmpdir, "queue.json")
        @state_file = File.join(@tmpdir, "state.json")
        @audit_file = File.join(@tmpdir, "audit.log")

        # Save and override env vars so the app uses our temp files
        @orig_env = {}
        %w[SENTINEL_QUEUE_PATH SENTINEL_STATE_PATH SENTINEL_AUDIT_LOG
           SENTINEL_BACKUP_GIST_ID GITHUB_TOKEN GITHUB_APP_ID
           GITHUB_APP_PRIVATE_KEY SCAN_TOKEN].each do |key|
            @orig_env[key] = ENV[key]
        end

        ENV["SENTINEL_QUEUE_PATH"] = @queue_file
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_AUDIT_LOG"] = @audit_file
        # Disable backup and GitHub auth to avoid real API calls
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        ENV.delete("GITHUB_TOKEN")
        ENV.delete("GITHUB_APP_ID")
        ENV.delete("GITHUB_APP_PRIVATE_KEY")
        ENV.delete("SCAN_TOKEN")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
        @orig_env.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------

    private

    def create_queue_with_findings(count: 3, repo: "owner/repo", type: "pr", files: nil, findings: nil)
        queue = Bot::Queue.new(@queue_file)
        findings ||= (1..count).map do |i|
            { rule: "rule-#{i}", severity: "high", file: "ci.yml",
              line: i * 10, message: "Finding #{i}", fix: "Fix #{i}" }
        end
        files ||= { ".github/workflows/ci.yml" => "patched content" }
        queue.add(
            repo: repo,
            title: "Security: Fix findings",
            body: "## Fix\nPatched vulnerabilities",
            files: files,
            findings: findings,
            type: type
        )
        queue.save
        [queue, queue.pending.first["id"]]
    end

    def reload_queue
        Bot::Queue.new(@queue_file)
    end

    def with_pr_writer_stub
        calls = []
        original_create_pr = Bot::PrWriter.instance_method(:create_pr)
        original_create_issue = Bot::PrWriter.instance_method(:create_issue)

        Bot::PrWriter.define_method(:create_pr) do |**kwargs|
            calls << { method: :create_pr, args: kwargs }
            { "html_url" => "https://github.com/test/repo/pull/99", "number" => 99 }
        end
        Bot::PrWriter.define_method(:create_issue) do |**kwargs|
            calls << { method: :create_issue, args: kwargs }
            { "html_url" => "https://github.com/test/repo/issues/99", "number" => 99 }
        end

        yield calls
    ensure
        Bot::PrWriter.define_method(:create_pr, original_create_pr)
        Bot::PrWriter.define_method(:create_issue, original_create_issue)
    end

    public

    # ---------------------------------------------------------------
    # POST /queue/:id/findings/:index/remove — Finding Removal
    # ---------------------------------------------------------------

    def test_remove_finding_valid_index_redirects_to_detail
        _queue, id = create_queue_with_findings(count: 3)

        post "/queue/#{id}/findings/1/remove"

        assert_equal 302, last_response.status
        location = last_response.headers["Location"]
        assert_match %r{/queue/#{id}}, location
        refute_match %r{\A/queue\?}, location  # NOT the list view

        reloaded = reload_queue
        item = reloaded.pending.first
        assert_equal 2, item["findings"].length
        # Index 1 was "rule-2"; remaining should be rule-1 and rule-3
        rules = item["findings"].map { |f| f["rule"] }
        assert_includes rules, "rule-1"
        assert_includes rules, "rule-3"
        refute_includes rules, "rule-2"
        assert_equal 3, item["original_finding_count"]
    end

    def test_remove_finding_flash_contains_rule_and_file
        _queue, id = create_queue_with_findings(count: 3)

        post "/queue/#{id}/findings/1/remove"

        assert_equal 302, last_response.status
        location = last_response.headers["Location"]
        # Flash should mention the removed finding's rule and file in the redirect URL
        assert_includes location, "flash="
        assert_includes location, "rule-2"
        assert_includes location, "ci.yml"
    end

    def test_remove_finding_out_of_bounds_returns_404
        _queue, id = create_queue_with_findings(count: 3)

        post "/queue/#{id}/findings/99/remove"

        assert_equal 404, last_response.status

        reloaded = reload_queue
        assert_equal 3, reloaded.pending.first["findings"].length
    end

    def test_remove_finding_negative_index_returns_404
        _queue, id = create_queue_with_findings(count: 3)

        post "/queue/#{id}/findings/-1/remove"

        assert_equal 404, last_response.status

        reloaded = reload_queue
        assert_equal 3, reloaded.pending.first["findings"].length
    end

    def test_remove_finding_non_integer_index_returns_404
        _queue, id = create_queue_with_findings(count: 3)

        post "/queue/#{id}/findings/abc/remove"

        assert_equal 404, last_response.status

        reloaded = reload_queue
        assert_equal 3, reloaded.pending.first["findings"].length
    end

    def test_remove_finding_nonexistent_queue_id_returns_404
        # No queue items created — empty queue
        post "/queue/nonexistent-id/findings/0/remove"

        assert_equal 404, last_response.status
        assert_includes last_response.body, "not found"
    end

    def test_remove_last_finding_auto_rejects_and_redirects_to_list
        _queue, id = create_queue_with_findings(count: 1)

        post "/queue/#{id}/findings/0/remove"

        assert_equal 302, last_response.status
        location = last_response.headers["Location"]
        # Should redirect to /queue (list view), not /queue/:id
        assert_match %r{/queue\?flash=}, location
        refute_match %r{/queue/#{id}}, location

        reloaded = reload_queue
        assert_equal 0, reloaded.pending.length
        assert_equal 1, reloaded.rejected.length
        assert_equal "All findings removed during review", reloaded.rejected.first["reason"]

        # Flash should mention rejection
        assert_includes location, "rejected"
    end

    def test_remove_finding_sets_original_finding_count_on_first_removal_only
        _queue, id = create_queue_with_findings(count: 3)

        # First removal
        post "/queue/#{id}/findings/0/remove"
        assert_equal 302, last_response.status

        reloaded = reload_queue
        item = reloaded.pending.first
        assert_equal 3, item["original_finding_count"]
        assert_equal 2, item["findings"].length

        # Second removal — original_finding_count must stay 3, not become 2
        post "/queue/#{id}/findings/0/remove"
        assert_equal 302, last_response.status

        reloaded = reload_queue
        item = reloaded.pending.first
        assert_equal 3, item["original_finding_count"], "original_finding_count must not change after first removal"
        assert_equal 1, item["findings"].length
    end

    # ---------------------------------------------------------------
    # GET /queue/:id — Detail View
    # ---------------------------------------------------------------

    def test_detail_view_contains_github_source_links
        _queue, id = create_queue_with_findings(
            count: 1,
            repo: "facebook/react",
            findings: [
                { rule: "shell-injection-expr", severity: "critical",
                  file: "ci.yml", line: 42, message: "Unsafe", fix: "Use env var" }
            ]
        )

        get "/queue/#{id}"

        assert_equal 200, last_response.status
        body = last_response.body
        assert_includes body, "https://github.com/facebook/react/blob/HEAD/.github/workflows/ci.yml#L42"
        assert_includes body, 'target="_blank"'
        assert_includes body, 'rel="noopener"'
    end

    def test_detail_view_contains_remove_buttons
        _queue, id = create_queue_with_findings(count: 3)

        get "/queue/#{id}"

        assert_equal 200, last_response.status
        body = last_response.body
        assert_includes body, "/queue/#{id}/findings/0/remove"
        assert_includes body, "/queue/#{id}/findings/1/remove"
        assert_includes body, "/queue/#{id}/findings/2/remove"
        assert_includes body, "btn-remove"
    end

    def test_detail_view_flash_message_displayed
        _queue, id = create_queue_with_findings(count: 1)

        get "/queue/#{id}?flash=Test+flash+message"

        assert_equal 200, last_response.status
        body = last_response.body
        assert_includes body, "Test flash message"
        assert_includes body, 'class="flash"'
    end

    def test_detail_view_finding_counter_after_removal
        _queue, id = create_queue_with_findings(count: 3)

        # Remove one finding to set original_finding_count
        post "/queue/#{id}/findings/0/remove"
        assert_equal 302, last_response.status

        get "/queue/#{id}"

        assert_equal 200, last_response.status
        body = last_response.body
        assert_includes body, "2 of 3"
    end

    def test_detail_view_finding_counter_standard_without_removal
        _queue, id = create_queue_with_findings(count: 3)

        get "/queue/#{id}"

        assert_equal 200, last_response.status
        body = last_response.body
        assert_includes body, "3 finding"
        # Should NOT show "of" in the findings counter when no curation has happened
        refute_includes body, "of 3 findings remaining"
    end

    def test_detail_view_external_links_have_target_blank
        _queue, id = create_queue_with_findings(
            count: 1,
            repo: "owner/repo"
        )

        get "/queue/#{id}"

        assert_equal 200, last_response.status
        body = last_response.body
        # Every external <a href="https://..."> should have target="_blank" rel="noopener"
        # Check the repo link in meta section
        assert_match(/github\.com\/owner\/repo.*?target="_blank".*?rel="noopener"/m, body)
    end

    # ---------------------------------------------------------------
    # POST /queue/:id/approve — Approve with Curation
    # ---------------------------------------------------------------

    def test_approve_with_curation_uses_curated_body
        _queue, id = create_queue_with_findings(count: 3)

        # Remove one finding to trigger curation
        post "/queue/#{id}/findings/0/remove"
        assert_equal 302, last_response.status

        ENV["GITHUB_TOKEN"] = "test-token"

        with_pr_writer_stub do |calls|
            post "/queue/#{id}/approve"

            assert_equal 200, last_response.status
            assert_equal 1, calls.length
            assert_equal :create_pr, calls.first[:method]

            body_arg = calls.first[:args][:body]
            assert_includes body_arg, "curated from 3 original"
            # Should reference remaining findings' rules (rule-2, rule-3)
            assert_includes body_arg, "rule-2"
            assert_includes body_arg, "rule-3"
            refute_includes body_arg, "rule-1"
        end
    end

    def test_approve_with_curation_filters_files
        files = {
            ".github/workflows/ci.yml" => "patched ci",
            ".github/workflows/deploy.yml" => "patched deploy",
        }
        findings = [
            { rule: "rule-ci", severity: "high", file: "ci.yml",
              line: 10, message: "CI finding", fix: "Fix CI" },
            { rule: "rule-deploy", severity: "high", file: "deploy.yml",
              line: 20, message: "Deploy finding", fix: "Fix deploy" },
        ]
        _queue, id = create_queue_with_findings(files: files, findings: findings)

        # Remove the deploy finding (index 1)
        post "/queue/#{id}/findings/1/remove"
        assert_equal 302, last_response.status

        ENV["GITHUB_TOKEN"] = "test-token"

        with_pr_writer_stub do |calls|
            post "/queue/#{id}/approve"

            assert_equal 200, last_response.status
            assert_equal 1, calls.length
            assert_equal :create_pr, calls.first[:method]

            files_arg = calls.first[:args][:files]
            assert files_arg.key?(".github/workflows/ci.yml"), "ci.yml should be in filtered files"
            refute files_arg.key?(".github/workflows/deploy.yml"), "deploy.yml should be filtered out"
        end
    end

    def test_approve_with_empty_filtered_files_changes_type_to_issue
        files = {
            ".github/workflows/ci.yml" => "patched ci",
        }
        findings = [
            { rule: "rule-ci", severity: "high", file: "ci.yml",
              line: 10, message: "CI finding", fix: "Fix CI" },
            { rule: "rule-advisory", severity: "medium", file: "advisory.yml",
              line: 5, message: "Advisory", fix: nil },
        ]
        _queue, id = create_queue_with_findings(
            type: "pr", files: files, findings: findings
        )

        # Remove the ci.yml finding (index 0) — only advisory.yml finding remains
        # but advisory.yml has no matching file in the files hash
        post "/queue/#{id}/findings/0/remove"
        assert_equal 302, last_response.status

        ENV["GITHUB_TOKEN"] = "test-token"

        with_pr_writer_stub do |calls|
            post "/queue/#{id}/approve"

            assert_equal 200, last_response.status
            assert_equal 1, calls.length
            # Should have switched to issue since no file patches remain
            assert_equal :create_issue, calls.first[:method]
            assert_includes last_response.body, "Issue created"
        end
    end

    def test_approve_without_curation_uses_original_body
        _queue, id = create_queue_with_findings(count: 3)
        # Do NOT remove any findings — no curation

        ENV["GITHUB_TOKEN"] = "test-token"

        with_pr_writer_stub do |calls|
            post "/queue/#{id}/approve"

            assert_equal 200, last_response.status
            assert_equal 1, calls.length
            assert_equal :create_pr, calls.first[:method]

            body_arg = calls.first[:args][:body]
            # Original body starts with "## Fix"
            assert_match(/\A## Fix/, body_arg)
            refute_includes body_arg, "curated from"

            files_arg = calls.first[:args][:files]
            assert files_arg.key?(".github/workflows/ci.yml"), "original files should be passed unchanged"
        end
    end

    # ---------------------------------------------------------------
    # GET /queue — List View
    # ---------------------------------------------------------------

    def test_list_view_repo_links_have_target_blank
        _queue, _id = create_queue_with_findings(count: 1, repo: "owner/repo")

        get "/queue"

        assert_equal 200, last_response.status
        body = last_response.body
        # Repo link should open in new tab
        assert_match(/github\.com\/owner\/repo.*?target="_blank".*?rel="noopener"/m, body)
    end
end

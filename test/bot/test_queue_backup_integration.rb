require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "json"
require "yaml"
require "time"

# Load bot modules — scanner_bot.rb pulls in all dependencies
$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/scanner_bot"

# ============================================================================
# Stub classes (reuse the same patterns from test_scanner_bot_integration.rb)
# ============================================================================

class QBIStubGitHubClient
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

class QBIStubSearch
    attr_accessor :candidates

    def initialize(token: nil)
        @candidates = []
    end

    def find_candidates(_query)
        @candidates
    end
end

class QBIStubScanner
    attr_accessor :scan_results

    def initialize
        @scan_results = {}
    end

    def scan(repo)
        @scan_results[repo] || { findings: [], output: "", workflow_count: 0 }
    end
end

class QBIStubPrWriter
    attr_accessor :created_prs, :pr_response, :created_issues, :issue_response

    def initialize(token: nil)
        @created_prs = []
        @pr_response = nil
        @created_issues = []
        @issue_response = nil
    end

    def create_pr(repo:, branch:, title:, body:, files:, signoff: nil)
        @created_prs << { repo: repo, branch: branch, title: title, body: body, files: files, signoff: signoff }
        @pr_response
    end

    def create_issue(repo:, title:, body:, labels: [])
        @created_issues << { repo: repo, title: title, body: body, labels: labels }
        @issue_response
    end
end

class QBIStubSync
    def initialize(token: nil, state: nil); end

    def sync_all
        { synced: 0, updated: 0, errors: 0 }
    end
end

# ============================================================================
# Integration Test: scan → queue → save → backup end-to-end
# ============================================================================

class TestQueueBackupIntegration < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-queue-backup-integration")
        @state_file = File.join(@tmpdir, "state.json")
        @queue_file = File.join(@tmpdir, "queue.json")
        @audit_file = File.join(@tmpdir, "audit.log")

        @stub_gh_client = QBIStubGitHubClient.new
        @stub_search = QBIStubSearch.new
        @stub_scanner = QBIStubScanner.new
        @stub_pr_writer = QBIStubPrWriter.new

        # Intercept GitHubClient.new to return our stub
        @original_gh_new = GitHubClient.method(:new)
        stub = @stub_gh_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }

        # Save and set ENV vars for the duration of the test
        @saved_env = {}
        %w[GITHUB_TOKEN SENTINEL_BACKUP_GIST_ID SENTINEL_STATE_PATH SENTINEL_QUEUE_PATH SENTINEL_BACKUP_AUTO GITHUB_APP_ID GITHUB_APP_PRIVATE_KEY].each do |key|
            @saved_env[key] = ENV[key]
        end

        ENV["GITHUB_TOKEN"] = "fake-test-token"
        ENV["SENTINEL_BACKUP_GIST_ID"] = "fake-gist-id-for-test"
        ENV["SENTINEL_STATE_PATH"] = @state_file
        ENV["SENTINEL_QUEUE_PATH"] = @queue_file
        ENV.delete("SENTINEL_BACKUP_AUTO")
        ENV.delete("GITHUB_APP_ID")
        ENV.delete("GITHUB_APP_PRIVATE_KEY")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)

        # Restore original GitHubClient.new
        original = @original_gh_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }

        # Restore ENV
        @saved_env.each { |key, val| val.nil? ? ENV.delete(key) : ENV[key] = val }
    end

    # Workflow YAML with a dangerous-triggers vulnerability (pull_request_target + checkout)
    def dangerous_trigger_workflow(name = "ci.yml")
        <<~YAML
            name: CI
            on:
              pull_request_target:
                types: [opened]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - name: Greet
                    run: |
                      echo "PR: ${{ github.event.pull_request.title }}"
        YAML
    end

    def make_shell_injection_finding(file: "ci.yml", line: 12)
        Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: file,
            line: line,
            code: 'echo "PR: ${{ github.event.pull_request.title }}"',
            message: "Untrusted input in shell command",
            fix: "Use env var indirection"
        )
    end

    def make_dangerous_trigger_finding(file: "ci.yml", line: 1)
        Finding.new(
            rule: "dangerous-triggers",
            severity: :critical,
            file: file,
            line: line,
            code: "on: pull_request_target",
            message: "Dangerous trigger with checkout",
            fix: "Review manually"
        )
    end

    # Build a ScannerBot with all external deps stubbed
    def build_bot(queue_mode: true, limit: nil)
        bot = nil
        _captured = capture_io do
            bot = Bot::ScannerBot.new(
                token: "fake-test-token",
                pattern: "dangerous-triggers",
                dry_run: false,
                limit: limit,
                queue_mode: queue_mode
            )
        end

        # Replace internal components with stubs
        bot.instance_variable_set(:@search, @stub_search)
        bot.instance_variable_set(:@scanner, @stub_scanner)
        bot.instance_variable_set(:@pr_writer, @stub_pr_writer)
        bot.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))
        bot.instance_variable_set(:@audit, Bot::Audit.new(@audit_file))

        # Stub sync_pr_statuses to be a no-op
        bot.define_singleton_method(:sync_pr_statuses) { }

        bot
    end

    # ========================================================================
    # THE TEST: Full scan → queue populate → queue save → gist backup flow
    #
    # This traces every step of the pipeline to find exactly where the queue
    # backup breaks.
    # ========================================================================

    def test_full_scan_queue_save_backup_flow
        # ----------------------------------------------------------------
        # STEP 1: Configure stubbed GitHub API responses
        # ----------------------------------------------------------------

        # Two candidate repos from search
        @stub_search.candidates = [
            { full_name: "owner/vuln-repo-1", stars: 1000 },
            { full_name: "owner/vuln-repo-2", stars: 500 },
        ]

        # Both repos have a shell-injection-expr finding (critical + auto-fixable)
        # plus a dangerous-triggers finding (critical + NOT auto-fixable, advisory)
        workflow_yaml = dangerous_trigger_workflow

        %w[owner/vuln-repo-1 owner/vuln-repo-2].each do |repo|
            finding_fixable = make_shell_injection_finding(line: 12)
            finding_advisory = make_dangerous_trigger_finding(line: 3)

            @stub_scanner.scan_results[repo] = {
                findings: [finding_fixable, finding_advisory],
                output: "",
                workflow_count: 1,
            }

            # Not sentinel-enabled
            @stub_gh_client.file_exists_map[[repo, ".github/.sentinel-ci.yml"]] = false
            @stub_gh_client.workflows = []
            # No opt-out file
            @stub_gh_client.file_exists_map[[repo, Bot::Config::OPT_OUT_FILE]] = false
            # Workflow file content
            @stub_gh_client.file_content_map[[repo, ".github/workflows/ci.yml"]] = workflow_yaml
        end

        # ----------------------------------------------------------------
        # STEP 2: Build bot and capture internal references
        # ----------------------------------------------------------------

        bot = build_bot(queue_mode: true)
        queue = bot.instance_variable_get(:@queue)
        state = bot.instance_variable_get(:@state)

        queue_path = queue.instance_variable_get(:@path)
        state_path = state.instance_variable_get(:@path)

        $stderr.puts "\n=== PATH DIAGNOSTICS ==="
        $stderr.puts "  Queue @path:   #{queue_path}"
        $stderr.puts "  State @path:   #{state_path}"
        $stderr.puts "  Queue file expected at: #{@queue_file}"
        $stderr.puts "  State file expected at: #{@state_file}"
        $stderr.puts "  Tmpdir: #{@tmpdir}"

        # Verify paths match our expectations
        assert_equal @queue_file, queue_path,
            "Queue @path should match @queue_file. Got #{queue_path} vs expected #{@queue_file}"
        assert_equal @state_file, state_path,
            "State @path should match @state_file. Got #{state_path} vs expected #{@state_file}"

        # ----------------------------------------------------------------
        # STEP 3: Intercept Backup to capture what it receives
        # ----------------------------------------------------------------

        # We need to intercept require_relative "backup" and the Backup.new call
        # that happens inside scanner_bot's run method (line 97-101).
        # We'll monkey-patch Backup.new temporarily to capture arguments + stub API.

        backup_new_calls = []
        backup_save_calls = []
        backup_files_sent = nil
        original_backup_new = Bot::Backup.method(:new)

        Bot::Backup.define_singleton_method(:new) do |**kwargs|
            backup_new_calls << kwargs.dup
            instance = original_backup_new.call(**kwargs)

            # Stub the API methods so we don't make real HTTP requests
            instance.define_singleton_method(:api_get) { |path| nil }
            instance.define_singleton_method(:api_post) { |path, body| nil }

            # Capture what gets sent to api_patch (the gist update)
            instance.define_singleton_method(:api_patch) { |path, body|
                backup_save_calls << { path: path, body: body }
                backup_files_sent = body[:files]
                { "id" => "fake-gist-id-for-test", "files" => {} }
            }

            instance
        end

        # ----------------------------------------------------------------
        # STEP 4: RUN THE BOT
        # ----------------------------------------------------------------

        captured = capture_io { bot.run }
        stdout_output = captured[0]
        stderr_output = captured[1]

        $stderr.puts "\n=== STDERR OUTPUT ==="
        $stderr.puts stderr_output

        # ----------------------------------------------------------------
        # STEP 5: ASSERT — Queue was populated
        # ----------------------------------------------------------------

        $stderr.puts "\n=== QUEUE STATE AFTER RUN ==="
        $stderr.puts "  queue.pending.length: #{queue.pending.length}"
        $stderr.puts "  queue.pending repos: #{queue.pending.map { |p| p["repo"] }.inspect}"

        assert queue.pending.length > 0,
            "Queue should have pending entries after scanning repos with critical findings. " \
            "Got #{queue.pending.length} pending entries."

        pending_repos = queue.pending.map { |p| p["repo"] }
        assert_includes pending_repos, "owner/vuln-repo-1",
            "Queue should contain entry for owner/vuln-repo-1"
        assert_includes pending_repos, "owner/vuln-repo-2",
            "Queue should contain entry for owner/vuln-repo-2"

        # Verify queue entries have correct structure
        queue.pending.each do |entry|
            refute_nil entry["id"], "Queue entry should have an id"
            refute_nil entry["repo"], "Queue entry should have a repo"
            refute_nil entry["title"], "Queue entry should have a title"
            refute_nil entry["body"], "Queue entry should have a body"
            refute_nil entry["findings"], "Queue entry should have findings"
            assert entry["findings"].length > 0, "Queue entry for #{entry["repo"]} should have at least one finding"
            refute_nil entry["queued_at"], "Queue entry should have queued_at timestamp"
        end

        # ----------------------------------------------------------------
        # STEP 6: ASSERT — Queue file was saved to disk
        # ----------------------------------------------------------------

        $stderr.puts "\n=== QUEUE FILE ON DISK ==="
        $stderr.puts "  Queue file exists at #{queue_path}? #{File.exist?(queue_path)}"

        assert File.exist?(queue_path),
            "Queue file should exist on disk at #{queue_path} after queue.save was called"

        queue_on_disk = JSON.parse(File.read(queue_path))
        $stderr.puts "  Queue file pending count: #{queue_on_disk["pending"]&.length}"
        $stderr.puts "  Queue file size: #{File.size(queue_path)} bytes"

        assert queue_on_disk["pending"].length > 0,
            "Queue file on disk should have pending entries"

        # ----------------------------------------------------------------
        # STEP 7: ASSERT — State file was saved to disk
        # ----------------------------------------------------------------

        $stderr.puts "\n=== STATE FILE ON DISK ==="
        $stderr.puts "  State file exists at #{state_path}? #{File.exist?(state_path)}"

        assert File.exist?(state_path),
            "State file should exist on disk at #{state_path} after state.save was called"

        state_on_disk = JSON.parse(File.read(state_path))
        $stderr.puts "  State repos count: #{state_on_disk["repos"]&.length}"

        assert state_on_disk["repos"].length > 0,
            "State file on disk should have repo entries"

        # ----------------------------------------------------------------
        # STEP 8: ASSERT — Backup was triggered with correct paths
        # ----------------------------------------------------------------

        $stderr.puts "\n=== BACKUP CALLS ==="
        $stderr.puts "  Backup.new called #{backup_new_calls.length} time(s)"
        backup_new_calls.each_with_index do |call, i|
            $stderr.puts "    Call #{i}: token=<redacted> state_path=#{call[:state_path]} queue_path=#{call[:queue_path]}"
        end

        assert backup_new_calls.length > 0,
            "Backup.new should have been called during bot.run"

        backup_call = backup_new_calls.first
        $stderr.puts "\n=== BACKUP PATH COMPARISON ==="
        $stderr.puts "  Backup received state_path: #{backup_call[:state_path]}"
        $stderr.puts "  State actual @path:         #{state_path}"
        $stderr.puts "  Backup received queue_path: #{backup_call[:queue_path]}"
        $stderr.puts "  Queue actual @path:         #{queue_path}"

        assert_equal state_path, backup_call[:state_path],
            "Backup should receive the same state_path that State uses. " \
            "Backup got: #{backup_call[:state_path]}, State has: #{state_path}"

        assert_equal queue_path, backup_call[:queue_path],
            "Backup should receive the same queue_path that Queue uses. " \
            "Backup got: #{backup_call[:queue_path]}, Queue has: #{queue_path}"

        # ----------------------------------------------------------------
        # STEP 9: ASSERT — Backup.save sent the queue file to the gist
        # ----------------------------------------------------------------

        $stderr.puts "\n=== BACKUP SAVE CALLS ==="
        $stderr.puts "  backup.save (api_patch) called #{backup_save_calls.length} time(s)"

        assert backup_save_calls.length > 0,
            "Backup.save should have called api_patch to update the gist"

        $stderr.puts "\n=== FILES SENT TO GIST ==="
        if backup_files_sent
            backup_files_sent.each do |filename, data|
                content_preview = data["content"]&.slice(0, 100) || "<nil>"
                $stderr.puts "  #{filename}: #{data["content"]&.length || 0} bytes (preview: #{content_preview}...)"
            end
        else
            $stderr.puts "  backup_files_sent is nil — no files were sent to the gist!"
        end

        refute_nil backup_files_sent,
            "Backup should have sent files to the gist"

        assert backup_files_sent.key?(Bot::Backup::STATE_GIST_FILENAME),
            "Backup should include #{Bot::Backup::STATE_GIST_FILENAME} in gist files. " \
            "Files sent: #{backup_files_sent&.keys&.inspect}"

        assert backup_files_sent.key?(Bot::Backup::QUEUE_GIST_FILENAME),
            "Backup should include #{Bot::Backup::QUEUE_GIST_FILENAME} in gist files. " \
            "Files sent: #{backup_files_sent&.keys&.inspect}. " \
            "Queue file exists at #{queue_path}? #{File.exist?(queue_path)}. " \
            "Backup queue_path was: #{backup_call[:queue_path]}. " \
            "File exists at backup queue_path? #{File.exist?(backup_call[:queue_path] || 'nil')}"

        # ----------------------------------------------------------------
        # STEP 10: ASSERT — Queue content in gist matches what's on disk
        # ----------------------------------------------------------------

        gist_queue_content = backup_files_sent[Bot::Backup::QUEUE_GIST_FILENAME]
        refute_nil gist_queue_content, "Gist should contain queue content"
        refute_nil gist_queue_content["content"], "Gist queue entry should have content"

        gist_queue_data = JSON.parse(gist_queue_content["content"])
        $stderr.puts "\n=== GIST QUEUE CONTENT ==="
        $stderr.puts "  Gist queue pending count: #{gist_queue_data["pending"]&.length}"

        assert_equal queue_on_disk["pending"].length, gist_queue_data["pending"].length,
            "Gist queue pending count should match disk queue pending count"

        # Verify the repos in the gist queue match
        gist_repos = gist_queue_data["pending"].map { |p| p["repo"] }
        assert_includes gist_repos, "owner/vuln-repo-1",
            "Gist queue should contain owner/vuln-repo-1"
        assert_includes gist_repos, "owner/vuln-repo-2",
            "Gist queue should contain owner/vuln-repo-2"

        # ----------------------------------------------------------------
        # STEP 11: Verify state in gist also has findings recorded
        # ----------------------------------------------------------------

        gist_state_content = backup_files_sent[Bot::Backup::STATE_GIST_FILENAME]
        refute_nil gist_state_content, "Gist should contain state content"
        gist_state_data = JSON.parse(gist_state_content["content"])

        $stderr.puts "\n=== GIST STATE CONTENT ==="
        $stderr.puts "  Gist state repos: #{gist_state_data["repos"]&.keys&.inspect}"

        assert gist_state_data["repos"].key?("owner/vuln-repo-1"),
            "Gist state should contain owner/vuln-repo-1"
        assert gist_state_data["repos"].key?("owner/vuln-repo-2"),
            "Gist state should contain owner/vuln-repo-2"

        # ----------------------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------------------

        summary = bot.instance_variable_get(:@summary)
        $stderr.puts "\n=== BOT RUN SUMMARY ==="
        $stderr.puts "  Scanned: #{summary[:scanned]}"
        $stderr.puts "  Findings: #{summary[:findings]}"
        $stderr.puts "  Queued: #{summary[:queued]}"
        $stderr.puts "  PRs opened: #{summary[:prs_opened]}"
        $stderr.puts "  Errors: #{summary[:errors]}"

        assert_equal 2, summary[:scanned], "Should have scanned 2 repos"
        assert summary[:findings] > 0, "Should have found critical findings"
        assert_equal 2, summary[:queued], "Should have queued 2 entries"
        assert_equal 0, summary[:prs_opened], "Should not have opened PRs (queue mode)"

        $stderr.puts "\n=== TEST PASSED: Full scan → queue → save → backup flow verified ==="

    ensure
        # Restore Backup.new
        if defined?(original_backup_new) && original_backup_new
            orig = original_backup_new
            Bot::Backup.define_singleton_method(:new) { |**kwargs| orig.call(**kwargs) }
        end
    end

    # ========================================================================
    # TEST 2: Reproduce production scenario — SENTINEL_STATE_PATH set,
    # SENTINEL_QUEUE_PATH NOT set. This simulates what happens on Railway
    # where state is at a custom path but queue uses its default.
    # ========================================================================

    # ========================================================================
    # TEST 2: Simulate production: state at custom path, queue at default.
    # Uses the SAME state/queue directories as production Docker container.
    # The bot's automatic backup (inside run) passes explicit queue_path,
    # so this should work -- but we verify end-to-end.
    # ========================================================================

    def test_production_layout_state_custom_queue_default
        # Simulate production: state at /data/state.json, queue at bot/queue.json
        # In Docker: WORKDIR=/sentinel, state at /sentinel/data/state.json
        custom_state_dir = File.join(@tmpdir, "data")
        custom_queue_dir = File.join(@tmpdir, "bot")
        FileUtils.mkdir_p(custom_state_dir)
        FileUtils.mkdir_p(custom_queue_dir)

        custom_state_path = File.join(custom_state_dir, "state.json")
        custom_queue_path = File.join(custom_queue_dir, "queue.json")

        ENV["SENTINEL_STATE_PATH"] = custom_state_path
        ENV["SENTINEL_QUEUE_PATH"] = custom_queue_path

        # One candidate repo
        @stub_search.candidates = [
            { full_name: "owner/prod-repo", stars: 1000 },
        ]

        finding = make_shell_injection_finding(line: 12)
        @stub_scanner.scan_results["owner/prod-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
        }

        @stub_gh_client.file_exists_map[["owner/prod-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_exists_map[["owner/prod-repo", Bot::Config::OPT_OUT_FILE]] = false
        @stub_gh_client.file_content_map[["owner/prod-repo", ".github/workflows/ci.yml"]] = dangerous_trigger_workflow

        bot = build_bot(queue_mode: true)

        # Override state/queue with explicit paths to simulate production layout
        bot.instance_variable_set(:@state, Bot::State.new(custom_state_path))
        bot.instance_variable_set(:@queue, Bot::Queue.new(custom_queue_path))

        queue = bot.instance_variable_get(:@queue)
        state = bot.instance_variable_get(:@state)

        queue_path = queue.instance_variable_get(:@path)
        state_path = state.instance_variable_get(:@path)

        $stderr.puts "\n=== PRODUCTION LAYOUT DIAGNOSTICS ==="
        $stderr.puts "  State @path:   #{state_path}"
        $stderr.puts "  Queue @path:   #{queue_path}"
        $stderr.puts "  State dir:     #{File.dirname(state_path)}"
        $stderr.puts "  Queue dir:     #{File.dirname(queue_path)}"
        $stderr.puts "  Same dir?      #{File.dirname(state_path) == File.dirname(queue_path)}"

        # Intercept Backup.new to capture what it receives
        backup_new_calls = []
        backup_files_sent = nil
        original_backup_new = Bot::Backup.method(:new)

        Bot::Backup.define_singleton_method(:new) do |**kwargs|
            backup_new_calls << kwargs.dup
            instance = original_backup_new.call(**kwargs)
            instance.define_singleton_method(:api_get) { |path| nil }
            instance.define_singleton_method(:api_post) { |path, body| nil }
            instance.define_singleton_method(:api_patch) { |path, body|
                backup_files_sent = body[:files]
                { "id" => "fake-gist-id-for-test", "files" => {} }
            }
            instance
        end

        captured = capture_io { bot.run }
        stderr_output = captured[1]
        $stderr.puts "\n=== STDERR ==="
        $stderr.puts stderr_output

        # Verify queue was populated
        assert queue.pending.length > 0,
            "Queue should have pending entries"
        assert File.exist?(queue_path),
            "Queue file should exist at #{queue_path}"

        # Verify backup was called with correct paths
        assert backup_new_calls.length > 0,
            "Backup.new should have been called"

        bc = backup_new_calls.first
        $stderr.puts "\n=== BACKUP PATH ANALYSIS ==="
        $stderr.puts "  Backup received state_path: #{bc[:state_path]}"
        $stderr.puts "  Backup received queue_path: #{bc[:queue_path]}"
        $stderr.puts "  State @path:                #{state_path}"
        $stderr.puts "  Queue @path:                #{queue_path}"
        $stderr.puts "  Paths match (state)? #{state_path == bc[:state_path]}"
        $stderr.puts "  Paths match (queue)? #{queue_path == bc[:queue_path]}"

        assert_equal state_path, bc[:state_path],
            "Backup state_path should match State @path"
        assert_equal queue_path, bc[:queue_path],
            "Backup queue_path should match Queue @path"

        # Verify both files in gist
        $stderr.puts "\n=== GIST FILES ==="
        if backup_files_sent
            backup_files_sent.each { |fn, d| $stderr.puts "  #{fn}: #{d["content"]&.length || 0} bytes" }
        else
            $stderr.puts "  (none)"
        end

        assert backup_files_sent&.key?(Bot::Backup::STATE_GIST_FILENAME),
            "Gist should contain state file"
        assert backup_files_sent&.key?(Bot::Backup::QUEUE_GIST_FILENAME),
            "Gist should contain queue file. " \
            "Queue at #{queue_path} (exists: #{File.exist?(queue_path)}). " \
            "Backup queue_path: #{bc[:queue_path]} (exists: #{File.exist?(bc[:queue_path] || "nil")})"

    ensure
        if defined?(original_backup_new) && original_backup_new
            orig = original_backup_new
            Bot::Backup.define_singleton_method(:new) { |**kwargs| orig.call(**kwargs) }
        end
    end

    # ========================================================================
    # TEST 3: CLI --backup path derivation bug.
    # When --backup is invoked separately (not via bot run), it does NOT
    # receive explicit queue_path. It derives queue_path from state_path.
    # If state and queue are in different directories, the derived path
    # is WRONG and the queue file is not found.
    # ========================================================================

    def test_cli_backup_misses_queue_when_paths_differ
        require_relative "../../bot/backup"

        # Simulate: state at /data/state.json, queue at /bot/queue.json
        state_dir = File.join(@tmpdir, "data")
        queue_dir = File.join(@tmpdir, "bot")
        FileUtils.mkdir_p(state_dir)
        FileUtils.mkdir_p(queue_dir)

        state_path = File.join(state_dir, "state.json")
        queue_path = File.join(queue_dir, "queue.json")

        # Write state and queue files
        state_data = { "repos" => { "owner/repo" => { "scans" => [{ "timestamp" => Time.now.utc.iso8601 }], "prs" => [] } }, "opt_outs" => [] }
        queue_data = { "pending" => [{ "id" => "test-1", "repo" => "owner/repo", "title" => "Fix", "body" => "b", "files" => {}, "findings" => [], "queued_at" => Time.now.utc.iso8601 }], "approved" => [], "rejected" => [] }

        File.write(state_path, JSON.pretty_generate(state_data))
        File.write(queue_path, JSON.pretty_generate(queue_data))

        ENV["SENTINEL_BACKUP_GIST_ID"] = "fake-gist-id-for-test"
        ENV.delete("SENTINEL_QUEUE_PATH")

        # Simulate what --backup CLI does: Backup.new(token: token)
        # This uses Config::STATE_FILE as default state_path and derives queue_path.
        # Since we can't change Config::STATE_FILE (it's a constant frozen at load time),
        # we simulate the exact same behavior: pass state_path, DON'T pass queue_path.
        backup = Bot::Backup.new(token: "fake-token", state_path: state_path)
        derived_queue_path = backup.instance_variable_get(:@queue_path)

        $stderr.puts "\n=== CLI --backup PATH DERIVATION ==="
        $stderr.puts "  state_path passed to Backup: #{state_path}"
        $stderr.puts "  queue_path derived by Backup: #{derived_queue_path}"
        $stderr.puts "  Actual queue file location:   #{queue_path}"
        $stderr.puts "  Derived == actual?            #{derived_queue_path == queue_path}"
        $stderr.puts "  File exists at derived path?  #{File.exist?(derived_queue_path)}"
        $stderr.puts "  File exists at actual path?   #{File.exist?(queue_path)}"

        # The derived path is WRONG — it's /data/queue.json, not /bot/queue.json
        expected_derived = File.join(state_dir, "queue.json")
        assert_equal expected_derived, derived_queue_path,
            "Backup should derive queue_path as sibling of state_path"

        # This is the BUG: the derived path doesn't match the actual queue location
        refute_equal queue_path, derived_queue_path,
            "When state and queue are in different dirs, derived path mismatches actual queue location"

        # Now stub API and attempt backup
        captured_files = nil
        backup.define_singleton_method(:api_patch) { |path, body|
            captured_files = body[:files]
            { "id" => "fake-gist-id-for-test", "files" => {} }
        }
        backup.define_singleton_method(:api_get) { |path| nil }
        backup.define_singleton_method(:api_post) { |path, body| nil }

        result = capture_io { backup.save }
        $stderr.puts result[1]

        $stderr.puts "\n=== CLI BACKUP RESULT ==="
        if captured_files
            captured_files.each { |fn, d| $stderr.puts "  #{fn}: #{d["content"]&.length || 0} bytes" }
        else
            $stderr.puts "  NO files sent to gist"
        end

        has_state = captured_files&.key?(Bot::Backup::STATE_GIST_FILENAME) || false
        has_queue = captured_files&.key?(Bot::Backup::QUEUE_GIST_FILENAME) || false

        $stderr.puts "  State in gist? #{has_state}"
        $stderr.puts "  Queue in gist? #{has_queue}"

        assert has_state,
            "State should be in the backup"

        # THIS ASSERTION REVEALS THE BUG:
        # The queue file EXISTS on disk at queue_path, but the CLI --backup
        # can't find it because it derived the wrong path.
        refute has_queue,
            "BUG CONFIRMED: CLI --backup does NOT include queue when state and queue " \
            "are in different directories. Backup looked at #{derived_queue_path} " \
            "but queue is at #{queue_path}."

        $stderr.puts "\n=== BUG CONFIRMED ==="
        $stderr.puts "  The CLI --backup command derives queue_path from state_path."
        $stderr.puts "  When SENTINEL_STATE_PATH points to a custom directory (e.g., /data/)"
        $stderr.puts "  but SENTINEL_QUEUE_PATH is not set, the queue defaults to bot/queue.json"
        $stderr.puts "  while the backup looks for data/queue.json. The queue is never found."
        $stderr.puts ""
        $stderr.puts "  This is the EXACT bug: the derived queue_path does not match"
        $stderr.puts "  where the Queue object actually writes its file."
        $stderr.puts ""
        $stderr.puts "  NOTE: The automatic backup inside bot.run() is NOT affected because"
        $stderr.puts "  scanner_bot.rb explicitly passes queue_path: @queue.instance_variable_get(:@path)."
        $stderr.puts "  Only the --backup CLI path and any external callers that don't pass"
        $stderr.puts "  queue_path explicitly are affected."
    end
end

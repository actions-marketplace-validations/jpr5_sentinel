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
# Stub classes for external dependencies
# ============================================================================

class StubGitHubClient
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

class StubSearch
    attr_accessor :candidates

    def initialize(token: nil)
        @candidates = []
    end

    def find_candidates(_query)
        @candidates
    end
end

class StubScanner
    attr_accessor :scan_results

    def initialize
        @scan_results = {}
    end

    def scan(repo)
        @scan_results[repo] || { findings: [], output: "", workflow_count: 0 }
    end
end

class StubPrWriter
    attr_accessor :created_prs, :pr_response

    def initialize(token: nil)
        @created_prs = []
        @pr_response = nil
    end

    def create_pr(repo:, branch:, title:, body:, files:, signoff: nil)
        @created_prs << {
            repo: repo, branch: branch, title: title,
            body: body, files: files, signoff: signoff
        }
        @pr_response
    end
end

class StubSync
    attr_accessor :sync_called

    def initialize(token: nil, state: nil)
        @sync_called = false
    end

    def sync_all
        @sync_called = true
        { synced: 0, updated: 0, errors: 0 }
    end
end

class StubShaResolver
    def resolve(_owner_action, _tag)
        "abc123def456abc123def456abc123def456abc1"
    end
end

# ============================================================================
# Integration Tests
# ============================================================================

class TestScannerBotIntegration < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-integration-test")
        @state_file = File.join(@tmpdir, "state.json")
        @queue_file = File.join(@tmpdir, "queue.json")
        @audit_file = File.join(@tmpdir, "audit.log")

        @stub_gh_client = StubGitHubClient.new
        @stub_search = StubSearch.new
        @stub_scanner = StubScanner.new
        @stub_pr_writer = StubPrWriter.new
        @stub_sync = StubSync.new

        # Intercept GitHubClient.new to return our stub
        @original_gh_new = GitHubClient.method(:new)
        stub = @stub_gh_client
        GitHubClient.define_singleton_method(:new) { |**kwargs| stub }
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)

        # Restore original GitHubClient.new
        original = @original_gh_new
        GitHubClient.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
    end

    # Helper: build a ScannerBot with all external deps stubbed out
    def build_bot(pattern: "shell-injection", dry_run: false, queue_mode: false, limit: nil)
        # Temporarily suppress GitHubAppAuth env check and PAT auth stderr
        bot = nil
        _captured = capture_io do
            bot = Bot::ScannerBot.new(
                token: "fake-token",
                pattern: pattern,
                dry_run: dry_run,
                limit: limit,
                queue_mode: queue_mode
            )
        end

        # Replace internal components with our stubs
        bot.instance_variable_set(:@search, @stub_search)
        bot.instance_variable_set(:@scanner, @stub_scanner)
        bot.instance_variable_set(:@pr_writer, @stub_pr_writer)
        bot.instance_variable_set(:@state, Bot::State.new(@state_file))
        bot.instance_variable_set(:@queue, Bot::Queue.new(@queue_file))
        bot.instance_variable_set(:@audit, Bot::Audit.new(@audit_file))

        # Stub sync_pr_statuses to use our stub
        sync_stub = @stub_sync
        bot.define_singleton_method(:sync_pr_statuses) do
            sync = sync_stub
            sync.sync_called = true
        end

        bot
    end

    # Helper: make a Finding with shell-injection-expr (critical, fixable)
    def make_shell_injection_finding(file: "ci.yml", line: 5)
        Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: file,
            line: line,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Untrusted input in shell command",
            fix: "Use env var indirection"
        )
    end

    # Helper: make a Finding that is critical but not auto-fixable
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

    # Helper: a workflow YAML with a known shell-injection-expr vulnerability
    def vulnerable_workflow_yaml
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

    # ========================================================================
    # Test 1: YAML validation gate
    # ========================================================================

    def test_yaml_validation_gate
        input = vulnerable_workflow_yaml
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 12,
            code: 'echo "PR: ${{ github.event.pull_request.title }}"',
            message: "Untrusted input in shell command",
            fix: "Use env var indirection"
        )

        result = AutoFix.apply(finding, input, sha_resolver: StubShaResolver.new)

        # Result must be valid YAML
        parsed = YAML.safe_load(result)
        refute_nil parsed, "AutoFix result must be parseable YAML"

        # Result must differ from input (a fix was applied)
        refute_equal input, result, "AutoFix should modify the input"

        # The dangerous ${{ }} expression should be replaced with env var indirection
        refute_match(/\$\{\{\s*github\.event\.pull_request\.title\s*\}\}/, result.split("env:").last.split("run:").last,
            "The run block should not contain the raw expression after fix")

        # Should have env var indirection
        assert_match(/PR_TITLE/, result, "Should contain PR_TITLE env var")
        assert_match(/\$PR_TITLE/, result, "Should use $PR_TITLE in run block")
    end

    # ========================================================================
    # Test 2: Duplicate PR detection
    # ========================================================================

    def test_duplicate_pr_detection
        state = Bot::State.new(@state_file)
        state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "shell-injection", 1)
        state.save

        reloaded = Bot::State.new(@state_file)
        assert reloaded.already_processed?("owner/repo", "shell-injection"),
            "already_processed? should return true for a recorded PR rule"

        # In the bot flow, already_processed repos are skipped and summary[:skipped] is incremented
        bot = build_bot(pattern: "shell-injection")
        # Manually set state with the pre-existing record
        bot_state = bot.instance_variable_get(:@state)
        bot_state.record_pr("owner/repo", "https://github.com/owner/repo/pull/1", "shell-injection", 1)

        @stub_search.candidates = [{ full_name: "owner/repo", stars: 500 }]

        _output = capture_io { bot.run }

        summary = bot.instance_variable_get(:@summary)
        assert_equal 1, summary[:skipped], "Bot should skip already-processed repos"
        assert_equal 0, summary[:scanned], "Bot should not scan already-processed repos"
    end

    # ========================================================================
    # Test 3: Opt-out respect
    # ========================================================================

    def test_opt_out_respect
        bot = build_bot(pattern: "shell-injection")
        bot_state = bot.instance_variable_get(:@state)
        bot_state.record_opt_out("owner/opted-out-repo")

        @stub_search.candidates = [{ full_name: "owner/opted-out-repo", stars: 500 }]

        _output = capture_io { bot.run }

        summary = bot.instance_variable_get(:@summary)
        assert_equal 1, summary[:skipped], "Bot should skip opted-out repos"
        assert_equal 0, summary[:scanned], "Bot should not scan opted-out repos"
    end

    # ========================================================================
    # Test 4: Rate limiting
    # ========================================================================

    def test_rate_limiting_stops_scanning
        bot = build_bot(pattern: "shell-injection")
        bot_state = bot.instance_variable_get(:@state)

        # Record MAX_PRS_PER_DAY PRs to trigger rate limit
        Bot::Config::MAX_PRS_PER_DAY.times do |i|
            bot_state.record_pr(
                "owner/repo#{i}",
                "https://github.com/owner/repo#{i}/pull/1",
                "shell-injection-expr",
                1
            )
        end

        assert bot_state.rate_limit_reached?, "Rate limit should be reached"

        @stub_search.candidates = [
            { full_name: "owner/new-repo", stars: 1000 },
            { full_name: "owner/another-repo", stars: 500 },
        ]

        captured = capture_io { bot.run }
        stderr_output = captured[1]

        assert_match(/Daily PR limit reached/, stderr_output,
            "Bot should log the rate limit message")

        summary = bot.instance_variable_get(:@summary)
        assert_equal 0, summary[:scanned], "Bot should not scan any repos when rate limited"
    end

    # ========================================================================
    # Test 5: Queue mode
    # ========================================================================

    def test_queue_mode_queues_instead_of_creating_pr
        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/vuln-repo", stars: 1000 }]
        @stub_scanner.scan_results["owner/vuln-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
        }

        # Set up the GitHubClient stub to provide workflow content and not find sentinel
        @stub_gh_client.file_exists_map[["owner/vuln-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_content_map[["owner/vuln-repo", ".github/workflows/ci.yml"]] = vulnerable_workflow_yaml

        _output = capture_io { bot.run }

        # Verify queue has a pending entry
        queue = bot.instance_variable_get(:@queue)
        pending = queue.pending
        assert_equal 1, pending.length, "Queue should have 1 pending entry"

        entry = pending.first
        assert_equal "owner/vuln-repo", entry["repo"]
        refute_nil entry["title"], "Queue entry should have a title"
        refute_nil entry["body"], "Queue entry should have a body"
        refute_nil entry["files"], "Queue entry should have files"
        assert entry["findings"].is_a?(Array), "Queue entry should have findings array"
        assert entry["findings"].length > 0, "Queue entry should have at least one finding"

        # PR writer should NOT have been called
        assert_empty @stub_pr_writer.created_prs,
            "PrWriter should not be called in queue mode"

        summary = bot.instance_variable_get(:@summary)
        assert_equal 1, summary[:queued], "Summary should show 1 queued"
        assert_equal 0, summary[:prs_opened], "Summary should show 0 PRs opened"
    end

    # ========================================================================
    # Test 6: Convention detection -- DCO
    # ========================================================================

    def test_dco_convention_detection
        @stub_gh_client.file_exists_map[["owner/dco-repo", ".github/dco.yml"]] = true

        # Test via the ScannerBot's repo_requires_dco? method
        bot = build_bot()

        # Access the private method for testing
        result = bot.send(:repo_requires_dco?, "owner/dco-repo")
        assert result, "repo_requires_dco? should return true when .github/dco.yml exists"
    end

    def test_dco_convention_returns_signoff_identity
        # When DCO is detected, the signoff should be Config::SIGNOFF_IDENTITY
        assert_equal "Jordan Ritter <jpr5@darkridge.com>", Bot::Config::SIGNOFF_IDENTITY,
            "SIGNOFF_IDENTITY constant should be set"
    end

    # ========================================================================
    # Test 7: Convention detection -- CLA skip
    # ========================================================================

    def test_cla_detection_via_contributing_md
        # Test through Bot::RepoConventions if available
        require_relative "../../bot/repo_conventions"

        @stub_gh_client.file_content_map[["owner/cla-repo", "CONTRIBUTING.md"]] =
            "You must sign the Google CLA before contributing."

        conventions = Bot::RepoConventions.new(token: "fake-token")
        result = conventions.detect_cla("owner/cla-repo")
        assert_equal :google, result, "Should detect Google CLA from CONTRIBUTING.md"
    end

    def test_cla_detection_generic
        require_relative "../../bot/repo_conventions"

        @stub_gh_client.file_content_map[["owner/cla-repo", "CONTRIBUTING.md"]] =
            "Please sign the Contributor License Agreement before submitting."

        conventions = Bot::RepoConventions.new(token: "fake-token")
        result = conventions.detect_cla("owner/cla-repo")
        assert_equal :generic, result, "Should detect generic CLA from CONTRIBUTING.md"
    end

    # ========================================================================
    # Test 8: Audit trail wiring
    # ========================================================================

    def test_audit_module_is_required
        # Bot::Audit should be defined (loaded via require_relative in scanner_bot.rb)
        assert defined?(Bot::Audit), "Bot::Audit class should be defined"
    end

    def test_audit_instance_exists_on_bot
        bot = build_bot()
        audit = bot.instance_variable_get(:@audit)
        assert_instance_of Bot::Audit, audit, "Bot should have an Audit instance"
    end

    def test_audit_run_start_called_during_run
        bot = build_bot(pattern: "shell-injection")
        @stub_search.candidates = []

        _output = capture_io { bot.run }

        # Check the audit log file for RUN_START entry
        assert File.exist?(@audit_file), "Audit log file should exist after run"
        log_content = File.read(@audit_file)
        assert_match(/RUN_START/, log_content, "Audit log should contain RUN_START")
        assert_match(/pattern=shell-injection/, log_content,
            "RUN_START should include the pattern")
    end

    def test_audit_run_end_called_during_run
        bot = build_bot(pattern: "shell-injection")
        @stub_search.candidates = []

        _output = capture_io { bot.run }

        log_content = File.read(@audit_file)
        assert_match(/RUN_END/, log_content, "Audit log should contain RUN_END")
    end

    def test_audit_skip_logged_for_opted_out_repo
        bot = build_bot(pattern: "shell-injection")
        bot_state = bot.instance_variable_get(:@state)
        bot_state.record_opt_out("owner/skip-me")

        @stub_search.candidates = [{ full_name: "owner/skip-me", stars: 500 }]

        _output = capture_io { bot.run }

        log_content = File.read(@audit_file)
        assert_match(/SKIP.*owner\/skip-me.*opted_out/, log_content,
            "Audit log should record skips with reason")
    end

    def test_audit_scan_logged_for_scanned_repo
        bot = build_bot(pattern: "shell-injection")

        @stub_search.candidates = [{ full_name: "owner/scan-me", stars: 500 }]
        @stub_scanner.scan_results["owner/scan-me"] = {
            findings: [],
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[["owner/scan-me", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []

        _output = capture_io { bot.run }

        log_content = File.read(@audit_file)
        assert_match(/SCAN.*owner\/scan-me/, log_content,
            "Audit log should record scans")
    end

    # ========================================================================
    # Test 9: Auto-sync at start of run
    # ========================================================================

    def test_sync_called_at_start_of_run
        bot = build_bot(pattern: "shell-injection")
        @stub_search.candidates = []

        _output = capture_io { bot.run }

        assert @stub_sync.sync_called,
            "sync_pr_statuses should be called at the start of run"
    end

    # ========================================================================
    # Test 10: record_pr passes 4 arguments
    # ========================================================================

    def test_record_pr_called_with_four_args_after_pr_creation
        bot = build_bot(pattern: "shell-injection", dry_run: false)

        # Use a dangerous-triggers finding (critical, not auto-fixable) so it becomes
        # an advisory finding. The bot will create an advisory-only PR.
        finding = make_dangerous_trigger_finding(file: "ci.yml", line: 1)
        @stub_search.candidates = [{ full_name: "owner/pr-repo", stars: 1000 }]
        @stub_scanner.scan_results["owner/pr-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
        }

        @stub_gh_client.file_exists_map[["owner/pr-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        # Provide the workflow content so the file grouping loop can fetch it
        @stub_gh_client.file_content_map[["owner/pr-repo", ".github/workflows/ci.yml"]] = vulnerable_workflow_yaml

        # The PR writer inside scan_and_fix is created fresh (not our @stub_pr_writer),
        # so we need to stub PrWriter.new to return our controlled stub.
        original_pw_new = Bot::PrWriter.method(:new)
        stub_writer = @stub_pr_writer
        stub_writer.pr_response = {
            "html_url" => "https://github.com/owner/pr-repo/pull/42",
            "number" => 42,
        }
        Bot::PrWriter.define_singleton_method(:new) { |**kwargs| stub_writer }

        # Track record_pr calls
        bot_state = bot.instance_variable_get(:@state)
        record_pr_calls = []
        original_record_pr = bot_state.method(:record_pr)
        bot_state.define_singleton_method(:record_pr) do |repo_name, url, rule, number|
            record_pr_calls << [repo_name, url, rule, number]
            original_record_pr.call(repo_name, url, rule, number)
        end

        _output = capture_io { bot.run }

        # Restore PrWriter.new
        Bot::PrWriter.define_singleton_method(:new) { |**kwargs| original_pw_new.call(**kwargs) }

        assert record_pr_calls.length > 0,
            "record_pr should have been called at least once"

        record_pr_calls.each do |call_args|
            assert_equal 4, call_args.length,
                "record_pr should be called with exactly 4 arguments (repo, url, rule, number)"
            repo_name, url, rule, number = call_args
            assert_equal "owner/pr-repo", repo_name
            assert_equal "https://github.com/owner/pr-repo/pull/42", url
            assert_kind_of String, rule, "rule should be a String"
            assert_equal 42, number, "number should be the PR number"
        end
    end

    # ========================================================================
    # Additional integration: full scan_and_fix flow with auto-fix
    # ========================================================================

    def test_full_scan_fix_flow_with_autofix
        bot = build_bot(pattern: "shell-injection", queue_mode: true)

        finding = make_shell_injection_finding(line: 12)
        @stub_search.candidates = [{ full_name: "owner/fix-repo", stars: 1000 }]
        @stub_scanner.scan_results["owner/fix-repo"] = {
            findings: [finding],
            output: "",
            workflow_count: 1,
        }

        workflow_content = vulnerable_workflow_yaml
        @stub_gh_client.file_exists_map[["owner/fix-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []
        @stub_gh_client.file_content_map[["owner/fix-repo", ".github/workflows/ci.yml"]] = workflow_content

        _output = capture_io { bot.run }

        summary = bot.instance_variable_get(:@summary)
        assert_equal 1, summary[:scanned], "Should have scanned 1 repo"
        assert summary[:findings] > 0, "Should have found findings"

        queue = bot.instance_variable_get(:@queue)
        pending = queue.pending
        assert_equal 1, pending.length, "Should have 1 queued entry"

        # Verify the queued files contain patched YAML
        entry = pending.first
        files = entry["files"]
        refute_empty files, "Queued entry should have patched files"

        # The patched content should be valid YAML
        files.each do |path, content|
            parsed = YAML.safe_load(content)
            refute_nil parsed, "Patched file #{path} must be parseable YAML"
        end
    end

    # ========================================================================
    # Additional: verify summary counts are correct across the flow
    # ========================================================================

    def test_summary_counts_with_mixed_repos
        bot = build_bot(pattern: "shell-injection")

        bot_state = bot.instance_variable_get(:@state)
        bot_state.record_opt_out("owner/opted-out")
        bot_state.record_pr("owner/already-done", "https://github.com/owner/already-done/pull/1", "shell-injection", 1)

        @stub_search.candidates = [
            { full_name: "owner/opted-out", stars: 500 },
            { full_name: "owner/already-done", stars: 500 },
            { full_name: "owner/clean-repo", stars: 500 },
        ]

        # clean-repo has no findings
        @stub_scanner.scan_results["owner/clean-repo"] = {
            findings: [],
            output: "",
            workflow_count: 1,
        }
        @stub_gh_client.file_exists_map[["owner/clean-repo", ".github/.sentinel-ci.yml"]] = false
        @stub_gh_client.workflows = []

        _output = capture_io { bot.run }

        summary = bot.instance_variable_get(:@summary)
        assert_equal 2, summary[:skipped], "Should skip opted-out + already-processed"
        assert_equal 1, summary[:scanned], "Should scan only the clean repo"
        assert_equal 0, summary[:findings], "Clean repo should have no findings"
    end
end

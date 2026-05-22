require_relative "../test_helper"
require "json"
require "net/http"

$LOAD_PATH.unshift(File.join(__dir__, "..", "..", "bot"))
require_relative "../../bot/slack_alert"

class TestSlackAlert < Minitest::Test
    # ========================================================================
    # enabled? / disabled behavior
    # ========================================================================

    def test_enabled_returns_false_when_env_var_not_set
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        refute Bot::SlackAlert.enabled?, "Should be disabled when SLACK_WEBHOOK_OSS_ALERTS is not set"
    end

    def test_enabled_returns_false_when_env_var_empty
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = ""
        refute Bot::SlackAlert.enabled?, "Should be disabled when SLACK_WEBHOOK_OSS_ALERTS is empty"
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
    end

    def test_enabled_returns_true_when_env_var_set
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = "https://hooks.slack.com/services/T00/B00/xxx"
        assert Bot::SlackAlert.enabled?, "Should be enabled when SLACK_WEBHOOK_OSS_ALERTS is set"
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
    end

    # ========================================================================
    # post is a no-op when disabled
    # ========================================================================

    def test_post_returns_nil_when_disabled
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        result = Bot::SlackAlert.post(
            repo: "CopilotKit/some-repo",
            findings: [make_finding]
        )
        assert_nil result, "post should return nil when disabled"
    end

    # ========================================================================
    # org_repo? classification
    # ========================================================================

    def test_org_repo_returns_true_for_copilotkit
        assert Bot::SlackAlert.org_repo?("CopilotKit/CopilotKit"),
            "CopilotKit repos should be org repos"
    end

    def test_org_repo_returns_true_for_ag_ui_protocol
        assert Bot::SlackAlert.org_repo?("ag-ui-protocol/ag-ui"),
            "ag-ui-protocol repos should be org repos"
    end

    def test_org_repo_returns_false_for_external_repo
        refute Bot::SlackAlert.org_repo?("facebook/react"),
            "External repos should not be org repos"
    end

    def test_org_repo_returns_false_for_nil
        refute Bot::SlackAlert.org_repo?(nil),
            "nil should not be an org repo"
    end

    # ========================================================================
    # Message formatting
    # ========================================================================

    def test_format_message_includes_repo_name
        findings = [make_finding(rule: "shell-injection-expr")]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/CopilotKit\/CopilotKit/, msg, "Message should include repo name")
    end

    def test_format_message_includes_finding_count
        findings = [
            make_finding(rule: "shell-injection-expr"),
            make_finding(rule: "unpinned-actions"),
        ]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/2/, msg, "Message should include finding count")
    end

    def test_format_message_includes_rule_names
        findings = [
            make_finding(rule: "shell-injection-expr"),
            make_finding(rule: "unpinned-actions"),
        ]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/shell-injection-expr/, msg, "Message should list rule names")
        assert_match(/unpinned-actions/, msg, "Message should list rule names")
    end

    def test_format_message_includes_severities_line
        findings = [
            make_finding(rule: "shell-injection-expr", severity: :critical),
            make_finding(rule: "unpinned-actions", severity: :high),
        ]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/Severities: critical, high/, msg, "Message should include a severities summary line")
    end

    def test_format_message_includes_severity
        findings = [make_finding(severity: :critical)]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/critical/i, msg, "Message should include severity")
    end

    def test_format_message_includes_file_and_line
        findings = [make_finding(file: "deploy.yml", line: 42)]
        msg = Bot::SlackAlert.format_message(
            repo: "CopilotKit/CopilotKit",
            findings: findings
        )
        assert_match(/deploy\.yml/, msg, "Message should include filename")
        assert_match(/42/, msg, "Message should include line number")
    end

    # ========================================================================
    # HTTP posting (with stubbed Net::HTTP)
    # ========================================================================

    def test_post_sends_http_request_when_enabled
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = "https://hooks.slack.com/services/T00/B00/xxx"
        http_calls = []

        # Stub Net::HTTP to capture the request
        original_post_form = Net::HTTP.method(:post_form)
        Net::HTTP.define_singleton_method(:post_form) do |uri, params|
            http_calls << { uri: uri.to_s, params: params }
            response = Net::HTTPSuccess.allocate
            response.define_singleton_method(:code) { "200" }
            response.define_singleton_method(:body) { "ok" }
            response
        end

        Bot::SlackAlert.post(
            repo: "CopilotKit/some-repo",
            findings: [make_finding]
        )

        assert_equal 1, http_calls.length, "Should make exactly one HTTP call"
        assert_equal "https://hooks.slack.com/services/T00/B00/xxx", http_calls.first[:uri]

        payload = JSON.parse(http_calls.first[:params]["payload"])
        assert payload.key?("text"), "Slack payload should have 'text' field"
        assert_match(/CopilotKit\/some-repo/, payload["text"], "Payload text should include repo")
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        Net::HTTP.define_singleton_method(:post_form, original_post_form) if original_post_form
    end

    def test_post_does_not_raise_on_http_failure
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = "https://hooks.slack.com/services/T00/B00/xxx"

        original_post_form = Net::HTTP.method(:post_form)
        Net::HTTP.define_singleton_method(:post_form) do |uri, params|
            raise Errno::ECONNREFUSED, "Connection refused"
        end

        # Should not raise -- errors are caught and logged
        result = nil
        _captured = capture_io do
            result = Bot::SlackAlert.post(
                repo: "CopilotKit/some-repo",
                findings: [make_finding]
            )
        end

        assert_nil result, "post should return nil on HTTP failure"
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        Net::HTTP.define_singleton_method(:post_form, original_post_form) if original_post_form
    end

    def test_post_logs_failure_to_stderr
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = "https://hooks.slack.com/services/T00/B00/xxx"

        original_post_form = Net::HTTP.method(:post_form)
        Net::HTTP.define_singleton_method(:post_form) do |uri, params|
            raise Errno::ECONNREFUSED, "Connection refused"
        end

        captured = capture_io do
            Bot::SlackAlert.post(
                repo: "CopilotKit/some-repo",
                findings: [make_finding]
            )
        end

        assert_match(/Slack alert failed.*Connection refused/i, captured[1],
            "Should log the failure to stderr")
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        Net::HTTP.define_singleton_method(:post_form, original_post_form) if original_post_form
    end

    def test_post_logs_non_2xx_response_to_stderr
        ENV["SLACK_WEBHOOK_OSS_ALERTS"] = "https://hooks.slack.com/services/T00/B00/xxx"

        original_post_form = Net::HTTP.method(:post_form)
        Net::HTTP.define_singleton_method(:post_form) do |uri, params|
            response = Net::HTTPForbidden.new("1.1", "403", "Forbidden")
            response.define_singleton_method(:code) { "403" }
            response.define_singleton_method(:body) { "invalid_token" }
            response
        end

        captured = capture_io do
            Bot::SlackAlert.post(
                repo: "CopilotKit/some-repo",
                findings: [make_finding]
            )
        end

        assert_match(/webhook returned 403/, captured[1],
            "Should log non-2xx response code to stderr")
        assert_match(/CopilotKit\/some-repo/, captured[1],
            "Should include repo name in the warning")
    ensure
        ENV.delete("SLACK_WEBHOOK_OSS_ALERTS")
        Net::HTTP.define_singleton_method(:post_form, original_post_form) if original_post_form
    end

    private

    def make_finding(rule: "shell-injection-expr", severity: :critical, file: "ci.yml", line: 10)
        Finding.new(
            rule: rule,
            severity: severity,
            file: file,
            line: line,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Untrusted input in shell command",
            fix: "Use env var indirection"
        )
    end
end

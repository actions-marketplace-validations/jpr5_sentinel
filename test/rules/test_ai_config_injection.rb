require_relative "../test_helper"

class TestAiConfigInjection < Minitest::Test
    def setup
        @rule = Rules::AiConfigInjection.new
    end

    # --- Rule metadata ---

    def test_rule_name
        assert_equal "ai-config-injection", @rule.name
    end

    def test_rule_severity
        assert_equal :critical, @rule.severity
    end

    def test_rule_description
        assert_match(/AI.*config/i, @rule.description)
    end

    # --- No PR trigger = no findings ---

    def test_no_flag_push_trigger
        yaml = <<~YAML
          on: push
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - uses: anthropics/claude-code-action@v1
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- PR trigger fires ---

    def test_flags_prt_with_claude_code_action
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
                - uses: anthropics/claude-code-action@v1
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/Claude Code/, findings.first.message)
        assert_match(/pull_request_target/, findings.first.message)
    end
end

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

    # --- Checkout semantics ---

    def test_no_flag_prt_default_checkout
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            label:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - uses: anthropics/claude-code-action@v1
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_pr_with_default_checkout_and_claude_cli
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: claude review --print
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_match(/Claude Code/, findings.first.message)
        assert_match(/pull_request/, findings.first.message)
    end

    def test_no_flag_pr_with_static_ref
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: main
                - uses: anthropics/claude-code-action@v1
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- AI tool variants ---

    def test_flags_prt_with_aider_action
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            fix:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.head_ref }}
                - uses: aider-ai/aider-action@v1
        YAML
        wf = Workflow.new(filename: "aider.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/Aider/, findings.first.message)
    end

    def test_flags_pr_with_copilot_cli
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: copilot review
        YAML
        wf = Workflow.new(filename: "copilot.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/Copilot/, findings.first.message)
    end

    def test_flags_sgpt_command
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: sgpt "review this code"
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/Shell GPT/, findings.first.message)
    end

    # --- Sanitization ---

    def test_no_flag_when_sanitized
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
                - run: rm -rf .claude/ .cursor/ && rm -f .mcp.json CLAUDE.md
                - uses: anthropics/claude-code-action@v1
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_partial_sanitization_counts
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: rm -f .mcp.json
                - run: claude review
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Working directory isolation ---

    def test_no_flag_isolated_working_directory
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    path: pr-code
                - uses: anthropics/claude-code-action@v1
                  with:
                    working-directory: safe-dir
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- No AI tool = no findings ---

    def test_no_flag_no_ai_tool
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: npm test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Severity differentiation ---

    def test_severity_critical_for_prt
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
                - run: claude review
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal :critical, findings.first.severity
    end

    def test_severity_high_for_pr
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: claude review
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal :high, findings.first.severity
    end

    def test_fix_message
        yaml = <<~YAML
          on: pull_request
          jobs:
            review:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: claude review
        YAML
        wf = Workflow.new(filename: "ai-review.yml", content: yaml)
        findings = @rule.check(wf)
        assert_match(/sanitization step/, findings.first.fix)
        assert_match(/rm -rf .claude\//, findings.first.fix)
    end
end

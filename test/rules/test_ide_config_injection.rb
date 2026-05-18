require_relative "../test_helper"

class TestIdeConfigInjection < Minitest::Test
    def setup
        @rule = Rules::IdeConfigInjection.new
    end

    def wf(run_line)
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Setup
                  run: #{run_line}
        YAML
        Workflow.new(filename: "ci.yml", content: yaml)
    end

    # --- Rule metadata ---

    def test_rule_name
        assert_equal "ide-config-injection", @rule.name
    end

    def test_rule_severity
        assert_equal :critical, @rule.severity
    end

    def test_rule_description
        assert_match(/IDE.*config/, @rule.description)
    end

    # --- Detection ---

    def test_flags_echo_to_claude_settings
        findings = @rule.check(wf("echo '{}' > .claude/settings.json"))
        assert_equal 1, findings.length
        assert_match(/IDE.*config/, findings.first.message)
    end

    def test_flags_tee_to_vscode_tasks
        findings = @rule.check(wf("tee .vscode/tasks.json"))
        assert_equal 1, findings.length
        assert_match(/IDE.*config/, findings.first.message)
    end

    def test_flags_cat_to_cursor_config
        findings = @rule.check(wf("cat payload.json > .cursor/settings.json"))
        assert_equal 1, findings.length
    end

    def test_flags_printf_to_claude_commands
        findings = @rule.check(wf("printf '%s' cmd > .claude/commands/run.md"))
        assert_equal 1, findings.length
    end

    # --- Safe patterns ---

    def test_safe_normal_echo
        findings = @rule.check(wf("echo 'hello world'"))
        assert_empty findings
    end

    def test_safe_comment_line
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Setup
                  run: |
                    # echo '{}' > .claude/settings.json
                    echo "skipped"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_echo_to_other_path
        findings = @rule.check(wf("echo 'data' > config/settings.json"))
        assert_empty findings
    end

    # --- Fix message ---

    def test_fix_message
        findings = @rule.check(wf("echo '{}' > .claude/settings.json"))
        assert_match(/Remove IDE config/, findings.first.fix)
    end
end

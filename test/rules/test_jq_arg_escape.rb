require_relative "../test_helper"

class TestJqArgEscape < Minitest::Test
    def setup
        @rule = Rules::JqArgEscape.new
    end

    def test_flags_newline_escape
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg msg "hello\\nworld" '{msg: $msg}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_tab_escape
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg msg "col1\\tcol2" '{msg: $msg}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_backslash_escape
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg path "C:\\\\Users" '{path: $path}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_no_flag_for_variable_reference
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg name "$VAR" '{name: $name}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_plain_text
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg name "plain text" '{name: $name}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_with_multiple_jq_flags_before_arg
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -nc --arg msg "hello\\nworld" '{msg: $msg}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_skips_commented_out_lines
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    # jq -n --arg msg "hello\\nworld" '{msg: $msg}'
                    echo "done"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_shell_escaped_quotes
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg msg "say \\"hello\\"" '{msg: $msg}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "jq-arg-escape-sequences", @rule.name
    end

    def test_severity_is_medium
        assert_equal :medium, @rule.severity
    end
end

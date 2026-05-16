require_relative "../test_helper"

class TestShellInjectionJq < Minitest::Test
    def setup
        @rule = Rules::ShellInjectionJq.new
    end

    def test_flags_jq_with_attacker_variable
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/PR_TITLE/, findings.first.message)
    end

    def test_flags_curl_with_attacker_variable
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Post to API
                  run: curl -X POST -d "${ISSUE_TITLE}" https://api.example.com
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/ISSUE_TITLE/, findings.first.message)
    end

    def test_no_flag_for_safe_variable_in_jq
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg sha "${GITHUB_SHA}" '{sha: $sha}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_branch_name_variable
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: jq -n --arg branch "${BRANCH_NAME}" '{branch: $branch}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_rule_name
        assert_equal "shell-injection-jq", @rule.name
    end
end

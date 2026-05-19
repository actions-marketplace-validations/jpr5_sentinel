require_relative "../test_helper"

class TestShellInjectionJq < Minitest::Test
    def setup
        @rule = Rules::ShellInjectionJq.new
    end

    def test_flags_jq_with_attacker_variable
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/PR_TITLE/, findings.first.message)
    end

    def test_flags_curl_with_attacker_variable
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Post to API
                  run: |
                    curl -X POST -d "${ISSUE_TITLE}" https://api.example.com
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/ISSUE_TITLE/, findings.first.message)
    end

    def test_no_flag_for_safe_variable_in_jq
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg sha "${GITHUB_SHA}" '{sha: $sha}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_branch_name_variable
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg branch "${BRANCH_NAME}" '{branch: $branch}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_jq_with_multiple_flags_before_arg
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -nc -r --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_no_flag_for_innocuous_var_with_attacker_substring
        # AUTHOR_VERIFIED should not match just because it contains AUTHOR
        assert_equal false, @rule.send(:potentially_attacker_controlled?, "AUTHOR_VERIFIED")
        assert_equal false, @rule.send(:potentially_attacker_controlled?, "MY_BRANCH_DATA")
    end

    def test_rule_name
        assert_equal "shell-injection-jq", @rule.name
    end

    # --- Step 4.1: Safe-trigger tests ---

    def test_no_flag_for_push_only_trigger
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_schedule_only_trigger
        yaml = <<~YAML
          on: schedule
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_still_flags_for_pull_request_trigger
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_still_flags_for_mixed_triggers_with_unsafe
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    # --- Step 4.2: Comment-skipping tests ---

    def test_no_flag_for_commented_out_line
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    # jq -n --arg title "${PR_TITLE}" '{title: $title}'
                    echo "safe"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_expr_only_in_trailing_comment
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    echo "safe" # jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Step 4.3: Env-block test ---

    def test_no_flag_in_env_block
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  env:
                    CMD: |
                      jq -n --arg title "${PR_TITLE}" '{title: $title}'
                  run: echo "$CMD"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Step 4.4: Guard tests ---

    def test_no_flag_with_step_guard
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  if: github.event_name == 'push'
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_job_guard
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              if: github.event_name != 'pull_request'
              runs-on: ubuntu-latest
              steps:
                - name: Build JSON
                  run: |
                    jq -n --arg title "${PR_TITLE}" '{title: $title}'
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

require_relative "../test_helper"

class TestShellInjectionExpr < Minitest::Test
    def setup
        @rule = Rules::ShellInjectionExpr.new
    end

    def test_flags_pr_title_in_run_block
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/pull_request\.title/, findings.first.message)
    end

    def test_no_flag_in_env_block
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  env:
                    PR_TITLE: ${{ github.event.pull_request.title }}
                  run: echo "$PR_TITLE"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_in_with_block
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: some/action@v1
                  with:
                    title: ${{ github.event.pull_request.title }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_safe_context_github_sha
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show SHA
                  run: echo "${{ github.sha }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_github_actor_in_run
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show actor
                  run: echo "${{ github.actor }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/github\.actor/, findings.first.message)
    end

    def test_flags_triggering_actor_in_run
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show actor
                  run: echo "${{ github.triggering_actor }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/triggering_actor/, findings.first.message)
    end

    def test_flags_head_ref_in_run
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show ref
                  run: echo "${{ github.head_ref }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_issue_body_in_run
        yaml = <<~YAML
          on: issues
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Process issue
                  run: |
                    echo "${{ github.event.issue.body }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_comment_body_in_run
        yaml = <<~YAML
          on: issue_comment
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Process comment
                  run: echo "${{ github.event.comment.body }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_rule_name
        assert_equal "shell-injection-expr", @rule.name
    end
end

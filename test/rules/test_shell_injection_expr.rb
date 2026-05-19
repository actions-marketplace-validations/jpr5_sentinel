require_relative "../test_helper"

class TestShellInjectionExpr < Minitest::Test
    def setup
        @rule = Rules::ShellInjectionExpr.new
    end

    def test_flags_pr_title_in_run_block
        yaml = <<~YAML
          on: pull_request
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
          on: pull_request
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
          on: pull_request
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

    def test_no_flag_github_actor_in_run
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show actor
                  run: echo "${{ github.actor }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_triggering_actor_in_run
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show actor
                  run: echo "${{ github.triggering_actor }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_head_ref_in_run
        yaml = <<~YAML
          on: pull_request
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

    def test_flags_inline_run_without_name
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_expr_in_run_block_after_env_block
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - env:
                    FOO: bar
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/pull_request\.title/, findings.first.message)
    end

    def test_no_flag_expr_inside_env_block_before_run
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    echo "hello"
                  env:
                    TITLE: ${{ github.event.pull_request.title }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_push_only_trigger
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
        assert_empty findings
    end

    def test_no_flag_for_workflow_dispatch_only_trigger
        yaml = <<~YAML
          on: workflow_dispatch
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show ref
                  run: echo "${{ github.head_ref }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_pull_request_trigger_with_head_ref
        yaml = <<~YAML
          on: pull_request
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

    def test_flags_mixed_triggers_with_unsafe
        yaml = <<~YAML
          on:
            push:
            pull_request:
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

    def test_no_flag_for_commented_out_line
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Show ref
                  run: |
                    # echo "${{ github.head_ref }}"
                    echo "safe"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_step_guard_excludes_pull_request
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe
                  if: github.event_name != 'pull_request'
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_job_guard_excludes_pull_request
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              if: github.event_name != 'pull_request'
              runs-on: ubuntu-latest
              steps:
                - name: Run
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_expr_only_in_trailing_comment
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe
                  run: |
                    echo "safe" # ${{ github.event.pull_request.title }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_still_flags_expr_before_trailing_comment
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Unsafe
                  run: |
                    echo "${{ github.event.pull_request.title }}" # some comment
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_adjacent_step_guard_does_not_protect_next_step
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Guarded
                  if: github.event_name == 'push'
                  run: echo "safe"
                - name: Unguarded
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_rule_name
        assert_equal "shell-injection-expr", @rule.name
    end
end

require_relative "../test_helper"
require_relative "../../lib/rules/concerns/guard_patterns"

class TestGuardPatterns < Minitest::Test
    # Create a minimal test harness that includes GuardPatterns
    class Harness
        include Rules::GuardPatterns
        # Make private methods accessible for testing
        public :guarded_by_step_if?, :guarded_by_job_if?, :safe_guard_condition?
    end

    def setup
        @harness = Harness.new
    end

    # --- safe_trigger_only? ---

    def test_safe_trigger_only_push
        wf = Workflow.new(filename: "ci.yml", content: "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert @harness.safe_trigger_only?(wf)
    end

    def test_safe_trigger_only_schedule
        wf = Workflow.new(filename: "ci.yml", content: "on: schedule\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert @harness.safe_trigger_only?(wf)
    end

    def test_safe_trigger_only_workflow_dispatch
        wf = Workflow.new(filename: "ci.yml", content: "on: workflow_dispatch\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        assert @harness.safe_trigger_only?(wf)
    end

    def test_not_safe_trigger_pull_request
        wf = Workflow.new(filename: "ci.yml", content: "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        refute @harness.safe_trigger_only?(wf)
    end

    def test_not_safe_trigger_mixed_with_unsafe
        yaml = "on:\n  push:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        refute @harness.safe_trigger_only?(wf)
    end

    def test_safe_trigger_multiple_safe
        yaml = "on:\n  push:\n  schedule:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        assert @harness.safe_trigger_only?(wf)
    end

    def test_safe_trigger_array_form
        yaml = "on: [push, schedule]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        assert @harness.safe_trigger_only?(wf)
    end

    def test_safe_trigger_empty_triggers
        wf = Workflow.new(filename: "ci.yml", content: "jobs:\n  build:\n    runs-on: ubuntu-latest\n")
        refute @harness.safe_trigger_only?(wf)
    end

    # --- strip_inline_comment ---

    def test_strip_trailing_comment
        line = '    echo "hello" # this is a comment'
        assert_equal '    echo "hello"', @harness.strip_inline_comment(line)
    end

    def test_no_strip_hash_inside_double_quotes
        line = '    run: echo "value # not a comment"'
        assert_equal '    run: echo "value # not a comment"', @harness.strip_inline_comment(line)
    end

    def test_no_strip_hash_inside_single_quotes
        line = "    run: echo 'value # not a comment'"
        assert_equal "    run: echo 'value # not a comment'", @harness.strip_inline_comment(line)
    end

    def test_strip_comment_after_quoted_string
        line = '    run: echo "hello" # trailing comment'
        assert_equal '    run: echo "hello"', @harness.strip_inline_comment(line)
    end

    def test_no_strip_no_comment
        line = '    run: echo "hello"'
        assert_equal '    run: echo "hello"', @harness.strip_inline_comment(line)
    end

    def test_strip_comment_with_expr_only_in_comment
        line = '    echo "safe" # ${{ github.event.pull_request.title }}'
        assert_equal '    echo "safe"', @harness.strip_inline_comment(line)
    end

    def test_no_strip_hash_without_preceding_space
        # A hash that is not preceded by whitespace should not be stripped
        # (e.g., a URL fragment or color code)
        line = '    run: echo https://example.com#fragment'
        assert_equal '    run: echo https://example.com#fragment', @harness.strip_inline_comment(line)
    end

    # --- guarded_by_safe_event? (step-level) ---

    def test_step_guard_excludes_pull_request_single_quotes
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: github.event_name != 'pull_request'
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        # Line 11 is the echo line with the dangerous expression
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert line_num, "Could not find target line in YAML"
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_step_guard_excludes_pull_request_double_quotes
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: github.event_name != "pull_request"
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_step_guard_with_expression_wrapper
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: ${{ github.event_name != 'pull_request' }}
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_step_guard_equals_push
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: github.event_name == 'push'
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_no_step_guard_still_flags
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Unsafe step
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        refute @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_adjacent_step_guard_does_not_leak
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Guarded step
                  if: github.event_name == 'push'
                  run: |
                    echo "safe"
                - name: Unguarded step
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        refute @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_step_guard_equals_safe_but_unrelated
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: github.event_name == 'schedule'
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    # --- guarded_by_safe_event? (job-level) ---

    def test_job_guard_excludes_pull_request
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
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_job_guard_equals_safe_trigger
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              if: github.event_name == 'push'
              runs-on: ubuntu-latest
              steps:
                - name: Run
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_no_job_guard_does_not_match
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Run
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        refute @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    def test_excludes_pull_request_target
        yaml = <<~YAML
          on:
            push:
            pull_request_target:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Safe step
                  if: github.event_name != 'pull_request_target'
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line_num = wf.raw_lines.index { |l| l.include?("github.event.pull_request.title") }
        assert @harness.guarded_by_safe_event?(wf, line_num + 1)
    end

    # --- safe_guard_condition? (unit tests for the private method) ---

    def test_safe_condition_not_equal_pull_request
        assert @harness.safe_guard_condition?("github.event_name != 'pull_request'")
    end

    def test_safe_condition_not_equal_pull_request_double_quotes
        assert @harness.safe_guard_condition?('github.event_name != "pull_request"')
    end

    def test_safe_condition_equals_push
        assert @harness.safe_guard_condition?("github.event_name == 'push'")
    end

    def test_safe_condition_equals_schedule
        assert @harness.safe_guard_condition?("github.event_name == 'schedule'")
    end

    def test_safe_condition_equals_workflow_call
        assert @harness.safe_guard_condition?("github.event_name == 'workflow_call'")
    end

    def test_unsafe_condition_equals_pull_request
        refute @harness.safe_guard_condition?("github.event_name == 'pull_request'")
    end

    def test_complex_condition_not_matched
        # Complex boolean expressions should NOT be matched (conservative)
        refute @harness.safe_guard_condition?("github.event_name == 'pull_request' && github.actor == 'dependabot'")
    end

    def test_condition_with_expression_wrapper
        assert @harness.safe_guard_condition?("${{ github.event_name != 'pull_request' }}")
    end

    def test_condition_equals_unsafe_trigger
        refute @harness.safe_guard_condition?("github.event_name == 'issues'")
    end
end

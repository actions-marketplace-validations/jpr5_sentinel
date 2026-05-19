require_relative "../test_helper"

class TestWorkflowDispatchInjection < Minitest::Test
    def setup
        @rule = Rules::WorkflowDispatchInjection.new
    end

    def test_flags_inputs_in_run_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name to greet"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_match(/inputs\.name/, findings.first.message)
    end

    def test_flags_github_event_inputs_in_run_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name to greet"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "Hello ${{ github.event.inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/github\.event\.inputs\.name/, findings.first.message)
    end

    def test_safe_in_env_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name to greet"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  env:
                    NAME: ${{ inputs.name }}
                  run: echo "Hello $NAME"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_input_in_run_block_after_env_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - env:
                    FOO: bar
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/inputs\.name/, findings.first.message)
    end

    def test_safe_in_with_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name to greet"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - uses: some/action@v1
                  with:
                    greeting: ${{ inputs.name }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Comment skipping (Step 5.1) ---

    def test_no_flag_for_commented_out_line
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    # echo "Hello ${{ inputs.name }}"
                    echo "safe"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_for_expr_only_in_trailing_comment
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "safe" # ${{ inputs.name }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Guard detection (Step 5.2) ---

    def test_no_flag_with_step_guard_equals_push
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
            push:
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  if: github.event_name == 'push'
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_job_guard
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
            push:
          jobs:
            greet:
              if: github.event_name == 'push'
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Regression tests: dispatch inputs must still be flagged (Step 5.3) ---

    def test_still_flags_workflow_dispatch_only
        # This is the critical behavior: workflow_dispatch_injection must NOT use
        # safe_trigger_only? because dispatch inputs are user-controlled.
        # workflow_dispatch IS in SAFE_TRIGGERS for other rules, but NOT for this one.
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_still_flags_without_guard
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                name:
                  description: "Name"
            push:
          jobs:
            greet:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "Hello ${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end
end

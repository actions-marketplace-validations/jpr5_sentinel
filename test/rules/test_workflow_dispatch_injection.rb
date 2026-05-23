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

    def test_flags_expr_in_trailing_comment
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
        assert_equal 1, findings.length
    end

    # --- Guard detection (Step 5.2) ---

    def test_flags_despite_step_guard_equals_push
        # Event guards do NOT protect against dispatch input injection —
        # inputs are always user-controlled regardless of which event fires.
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
        assert_equal 1, findings.length
    end

    def test_flags_despite_job_guard
        # Event guards do NOT protect against dispatch input injection —
        # inputs are always user-controlled regardless of which event fires.
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
        assert_equal 1, findings.length
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

    # --- Execution context differentiation (non-shell contexts) ---

    def test_no_flag_for_inputs_in_body_multiline_field
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Release scope"
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Build
                  run: |
                    echo "step 1"
                    echo "step 2"
                    echo "step 3"
                - uses: peter-evans/create-pull-request@v5
                  with:
                    title: "Release"
                    body: |
                      ## Release

                      Scope: ${{ inputs.scope }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "body: field under with: is not shell — should not fire"
    end

    def test_no_flag_for_github_event_inputs_in_body_field
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Release scope"
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Build
                  run: echo "done"
                - uses: peter-evans/create-pull-request@v5
                  with:
                    body: |
                      ## Release

                      Scope: ${{ github.event.inputs.scope }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "body: field with github.event.inputs is not shell — should not fire"
    end

    def test_no_flag_for_inputs_in_deeply_nested_with_parameter
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Build
                  run: |
                    echo "build"
                    echo "more build"
                - uses: some/action@v1
                  with:
                    nested:
                      deep:
                        scope: ${{ inputs.scope }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "deeply nested with: parameter is not shell — should not fire"
    end

    def test_no_flag_for_inputs_in_github_script_with_field
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Script
                  run: |
                    echo "hello"
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const scope = "${{ inputs.scope }}";
                      console.log(scope);
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "github-script with: script: is handled by a separate rule — should not fire here"
    end

    def test_no_flag_for_inputs_in_workflow_level_env
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          env:
            SCOPE: ${{ inputs.scope }}
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: echo "$SCOPE"
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "workflow-level env: is safe — should not fire"
    end

    def test_no_flag_for_inputs_in_job_outputs
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            setup:
              runs-on: ubuntu-latest
              outputs:
                scope: ${{ inputs.scope }}
              steps:
                - run: echo "setup"
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "job outputs: is not shell — should not fire"
    end

    def test_no_flag_for_inputs_in_concurrency_group
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          concurrency:
            group: release-${{ inputs.scope }}
            cancel-in-progress: true
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: echo "go"
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "concurrency group: is not shell — should not fire"
    end

    def test_no_flag_for_inputs_in_step_if_condition
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Conditional
                  if: ${{ inputs.scope == 'runtime' }}
                  uses: some/action@v1
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "if: condition is expression context, not shell — should not fire"
    end

    # --- Mixed real-world workflow: only run: should fire ---

    def test_real_world_mixed_workflow_only_flags_run_block
        yaml = <<~YAML
          name: Stable Release
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Package scope"
                  required: true
                  type: string
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Checkout
                  uses: actions/checkout@v4

                - name: Install
                  run: pnpm install --frozen-lockfile

                - name: Publish
                  run: pnpm publish --filter ${{ inputs.scope }}

                - name: Create PR
                  uses: peter-evans/create-pull-request@v5
                  with:
                    title: "chore: release ${{ inputs.scope }}"
                    body: |
                      ## Release ${{ inputs.scope }}

                      Automated release PR.
                    branch: release/${{ inputs.scope }}
        YAML
        wf = Workflow.new(filename: "stable-release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "only the run: block should fire, not with:/body:"
        assert_match(/inputs\.scope/, findings.first.message)
        assert_match(/pnpm publish/, findings.first.code)
    end

    # --- Bug A: Long run blocks exceed backward-scan cap ---

    def test_fires_when_inputs_in_long_run_block
        # Build a run block with ~60 lines of filler before the injection.
        # The old 20-line lookback cap would miss the run: key.
        filler = (1..55).map { |n| "        echo \"line #{n}\"" }.join("\n")
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Long script
                  run: |
        #{filler}
                    echo "${{ inputs.scope }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect input in long run block (60+ lines from run: key)"
        assert_match(/inputs\.scope/, findings.first.message)
    end

    # --- Bug B: Uncommon step-starting keys not recognized ---

    def test_fires_when_step_starts_with_working_directory
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - working-directory: /tmp
                  run: echo "${{ inputs.scope }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect input when step starts with working-directory:"
    end

    def test_fires_when_step_starts_with_continue_on_error
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - continue-on-error: true
                  run: echo "${{ inputs.scope }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect input when step starts with continue-on-error:"
    end

    def test_fires_when_step_starts_with_shell
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - shell: bash
                  run: echo "${{ inputs.scope }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect input when step starts with shell:"
    end

    def test_no_false_positive_for_run_key_inside_with_block
        # An action input parameter named "run" inside a with: block should NOT
        # be treated as a shell run: block. The `run:` is at a deeper indent
        # than with:, so it's an action parameter, not a step-level run: key.
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                cmd:
                  description: "Command"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: some/action@v1
                  with:
                    run: ${{ inputs.cmd }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "run: inside with: is an action parameter, not shell — should not fire"
    end

    def test_no_false_positive_for_run_key_inside_with_block_multiline
        # Same as above but with a multiline value.
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                cmd:
                  description: "Command"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: some/action@v1
                  with:
                    run: |
                      ${{ inputs.cmd }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "multiline run: inside with: is an action parameter — should not fire"
    end

    def test_still_fires_for_step_level_run_with_inputs
        # A step-level run: (at the same indent as uses:/with:/name:) must
        # still be flagged. This is the true positive counterpart.
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                cmd:
                  description: "Command"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Execute
                  run: ${{ inputs.cmd }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "step-level run: with input must fire"
        assert_match(/inputs\.cmd/, findings.first.message)
    end

    def test_no_false_positive_for_input_on_unrecognized_step_key
        # If continue-on-error is not recognized as a step boundary, the backward
        # scan passes through it into a previous step's run: block, causing a
        # false positive (reporting an injection that isn't in a run block).
        yaml = <<~YAML
          on:
            workflow_dispatch:
              inputs:
                scope:
                  description: "Scope"
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Builder
                  run: |
                    echo "building"
                - continue-on-error: ${{ inputs.scope }}
                  uses: some/action@v1
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "Input on continue-on-error: line is not in a run block — should not fire"
    end
end

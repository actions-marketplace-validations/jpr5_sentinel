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
end

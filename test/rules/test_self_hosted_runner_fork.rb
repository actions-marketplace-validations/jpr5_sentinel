require_relative "../test_helper"

class TestSelfHostedRunnerFork < Minitest::Test
    def setup
        @rule = Rules::SelfHostedRunnerFork.new
    end

    def test_flags_self_hosted_with_pull_request
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
                - run: echo "building"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/self-hosted.*pull_request/i, findings.first.message)
    end

    def test_safe_with_github_hosted_runner
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: echo "building"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_with_self_hosted_push_only
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
                - run: echo "building"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_multiple_self_hosted_jobs
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
            test:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 2, findings.length
    end

    def test_flags_self_hosted_with_mixed_runners
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
            deploy:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_safe_with_self_hosted_labeled_gate
        yaml = <<~YAML
          on:
            pull_request:
              types: [labeled]
          jobs:
            build:
              runs-on: self-hosted
              steps:
                - uses: actions/checkout@v4
                - run: echo "building"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

require_relative "../test_helper"

class TestMissingTimeouts < Minitest::Test
    def setup
        @rule = Rules::MissingTimeouts.new
    end

    def test_flags_job_without_timeout
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_match(/no timeout-minutes/, findings.first.message)
    end

    def test_safe_with_timeout_minutes
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              timeout-minutes: 15
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_multiple_jobs_one_missing
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              timeout-minutes: 15
              steps:
                - run: echo "build"
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: echo "deploy"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/deploy/, findings.first.message)
    end

    def test_rule_name
        assert_equal "missing-timeouts", @rule.name
    end
end

require_relative "../test_helper"

class TestUnpinnedActions < Minitest::Test
    def setup
        @rule = Rules::UnpinnedActions.new
    end

    def test_flags_tag_pinned_third_party
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: pnpm/action-setup@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
    end

    def test_sha_pinned_action_no_flag
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_local_action_no_flag
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: ./my-action
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_docker_action_no_flag
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker://alpine:3.18
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_first_party_severity_low
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :low, findings.first.severity
    end

    def test_github_first_party_severity_low
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: github/codeql-action/analyze@v3
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :low, findings.first.severity
    end

    def test_multiple_actions_mixed
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
                - uses: pnpm/action-setup@v4
                - uses: ./local-action
                - uses: actions/setup-node@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        # pnpm/action-setup@v4 -> medium, actions/setup-node@v4 -> low
        assert_equal 2, findings.length
        severities = findings.map(&:severity)
        assert_includes severities, :medium
        assert_includes severities, :low
    end

    def test_rule_name
        assert_equal "unpinned-actions", @rule.name
    end

    def test_rule_severity
        assert_equal :medium, @rule.severity
    end
end

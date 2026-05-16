require_relative "../test_helper"

class TestDangerousTriggers < Minitest::Test
    def setup
        @rule = Rules::DangerousTriggers.new
    end

    def test_flags_prt_with_pr_head_checkout
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/pull_request_target/, findings.first.message)
    end

    def test_no_flag_prt_without_checkout
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            label:
              runs-on: ubuntu-latest
              steps:
                - run: echo "just labeling"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_regular_pr_with_checkout
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_prt_checkout_default_ref
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_prt_with_head_ref
        yaml = <<~YAML
          on: pull_request_target
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.head_ref }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_rule_name
        assert_equal "dangerous-triggers", @rule.name
    end
end

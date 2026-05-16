require_relative "../test_helper"

class TestMissingPermissions < Minitest::Test
    def setup
        @rule = Rules::MissingPermissions.new
    end

    def test_flags_missing_permissions
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_match(/permissions/, findings.first.message)
    end

    def test_no_flag_with_permissions
        yaml = <<~YAML
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_empty_permissions
        yaml = <<~YAML
          on: push
          permissions: {}
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "missing-permissions", @rule.name
    end
end

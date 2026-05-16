require_relative "../test_helper"

class TestOverlyBroadTriggers < Minitest::Test
    def setup
        @rule = Rules::OverlyBroadTriggers.new
    end

    def test_flags_push_no_filters
        # push: {} produces a truthy empty hash that the rule recognizes
        # as an unfiltered trigger (no branches/paths/tags keys)
        yaml = <<~YAML
          on:
            push: {}
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        push_findings = findings.select { |f| f.code&.include?("push") }
        assert_operator push_findings.length, :>=, 1
        assert_equal :low, push_findings.first.severity
    end

    def test_no_flag_push_with_branches
        yaml = <<~YAML
          on:
            push:
              branches: [main]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        push_findings = findings.select { |f| f.code&.include?("push") }
        assert_empty push_findings
    end

    def test_no_flag_push_with_branches_ignore
        yaml = <<~YAML
          on:
            push:
              branches-ignore: [experimental]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        push_findings = findings.select { |f| f.code&.include?("push") }
        assert_empty push_findings
    end

    def test_no_flag_push_with_paths
        yaml = <<~YAML
          on:
            push:
              paths: ["src/**"]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        push_findings = findings.select { |f| f.code&.include?("push") }
        assert_empty push_findings
    end

    def test_no_flag_push_with_tags
        yaml = <<~YAML
          on:
            push:
              tags: ["v*"]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        push_findings = findings.select { |f| f.code&.include?("push") }
        assert_empty push_findings
    end

    def test_flags_pull_request_no_filters
        yaml = <<~YAML
          on:
            pull_request: {}
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        pr_findings = findings.select { |f| f.code&.include?("pull_request") }
        assert_operator pr_findings.length, :>=, 1
    end

    def test_rule_name
        assert_equal "overly-broad-triggers", @rule.name
    end
end

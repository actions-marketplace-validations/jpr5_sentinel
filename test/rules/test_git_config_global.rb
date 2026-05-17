require_relative "../test_helper"

class TestGitConfigGlobal < Minitest::Test
    def setup
        @rule = Rules::GitConfigGlobal.new
    end

    def test_flags_global_insteadof
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: git config --global url."https://x-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :low, findings.first.severity
        assert_match(/--global/, findings.first.message)
    end

    def test_flags_global_credential
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: git config --global credential.helper store
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/credential/, findings.first.code)
    end

    def test_safe_with_local_config
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: git config --local url."https://x-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_global_user_name
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: git config --global user.name "CI Bot"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "git-config-global", @rule.name
    end
end

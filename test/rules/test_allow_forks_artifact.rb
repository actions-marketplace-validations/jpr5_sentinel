require_relative "../test_helper"

class TestAllowForksArtifact < Minitest::Test
    def setup
        @rule = Rules::AllowForksArtifact.new
    end

    def test_flags_allow_forks_true
        yaml = <<~YAML
          on: workflow_run
          jobs:
            process:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                  with:
                    allow_forks: true
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_match(/fork-produced artifacts/, findings.first.message)
    end

    def test_safe_without_allow_forks
        yaml = <<~YAML
          on: workflow_run
          jobs:
            process:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_with_allow_forks_false
        yaml = <<~YAML
          on: workflow_run
          jobs:
            process:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                  with:
                    allow_forks: false
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "allow-forks-artifact", @rule.name
    end
end

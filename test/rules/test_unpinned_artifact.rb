require_relative "../test_helper"

class TestUnpinnedArtifact < Minitest::Test
    def setup
        @rule = Rules::UnpinnedArtifact.new
    end

    def test_flags_download_artifact_without_name
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                - run: ls -la
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "unpinned-artifact", findings.first.rule
        assert_match(/without specific name/, findings.first.message)
    end

    def test_safe_with_specific_name
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                  with:
                    name: build-output
                - run: ls -la
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_download_artifact_with_empty_with_block
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                  with:
                    path: ./dist
                - run: ls -la
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_match(/without specific name/, findings.first.message)
    end

    def test_safe_with_name_specified
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                  with:
                    name: my-artifact
                    path: ./dist
                - run: ls -la
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

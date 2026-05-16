require_relative "../test_helper"

class TestUnpinnedDockerImage < Minitest::Test
    def setup
        @rule = Rules::UnpinnedDockerImage.new
    end

    def test_flags_docker_protocol_latest
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker://node:latest
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :low, findings.first.severity
        assert_match(/:latest/, findings.first.message)
    end

    def test_flags_image_latest
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              container:
                image: node:latest
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/:latest/, findings.first.message)
    end

    def test_safe_with_sha_digest
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              container:
                image: node@sha256:abc123def456
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_with_specific_tag
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              container:
                image: node:18.17.0
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "unpinned-docker-image", @rule.name
    end
end

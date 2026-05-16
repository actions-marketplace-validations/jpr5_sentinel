require_relative "../test_helper"

class TestCurlPipeShell < Minitest::Test
    def setup
        @rule = Rules::CurlPipeShell.new
    end

    def test_flags_curl_pipe_sh
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: curl -fsSL https://example.com/install.sh | sh
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end

    def test_flags_curl_pipe_bash
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: curl -fsSL https://example.com/install.sh | bash
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_wget_pipe_sh
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: wget -q https://example.com/install.sh -O - | sh
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_no_flag_commented_out
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: |
                    # curl -fsSL https://example.com/install.sh | sh
                    echo "doing it properly"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_curl_without_pipe
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Download
                  run: curl -fsSL -o installer.sh https://example.com/install.sh
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_curl_pipe_sudo_sh
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: curl -fsSL https://example.com/install.sh | sudo sh
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_curl_pipe_sudo_bash
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: curl -fsSL https://example.com/install.sh | sudo bash
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_rule_name
        assert_equal "curl-pipe-shell", @rule.name
    end
end

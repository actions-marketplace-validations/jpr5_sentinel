require_relative "../test_helper"

class TestCredentialWindow < Minitest::Test
    def setup
        @rule = Rules::CredentialWindow.new
    end

    def test_flags_large_gap_between_config_and_push
        # MAX_STEPS_BETWEEN is 5, so gap > 5 should flag
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
                - run: echo step1
                - run: echo step2
                - run: echo step3
                - run: echo step4
                - run: echo step5
                - run: echo step6
                - run: git push origin main
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_match(/steps before push/, findings.first.message)
    end

    def test_no_flag_small_gap
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
                - run: echo build
                - run: git push origin main
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_without_push
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
                - run: echo done
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_without_git_config
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: echo step1
                - run: git push origin main
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "credential-window", @rule.name
    end
end

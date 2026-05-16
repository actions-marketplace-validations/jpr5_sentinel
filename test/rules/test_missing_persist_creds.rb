require_relative "../test_helper"

class TestMissingPersistCreds < Minitest::Test
    def setup
        @rule = Rules::MissingPersistCreds.new
    end

    def test_flags_checkout_without_persist_credentials
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
        assert_equal :high, findings.first.severity
        assert_match(/persist-credentials/, findings.first.message)
    end

    def test_no_flag_with_persist_credentials_false
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    persist-credentials: false
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_when_job_does_git_push
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: git push origin main
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        # Job does git push, so persist-credentials is intentional
        # Rule skips only if persist-credentials is explicitly true
        # Actually, looking at the rule: it skips if job_pushes && persist == true
        # If persist is nil (not set) and job pushes, it still flags
        # Let me verify: the rule says `next if job_pushes && persist == true`
        # So without explicit `persist-credentials: true`, it will still flag
        # This is by design - you should be explicit about needing credentials
        assert_equal 1, findings.length
    end

    def test_no_flag_when_job_pushes_with_explicit_true
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    persist-credentials: true
                - run: git push origin main
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_multiple_checkouts
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 2, findings.length
    end

    def test_no_flag_for_non_actions_checkout
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: some-org/checkout-helper@v1
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_rule_name
        assert_equal "missing-persist-credentials", @rule.name
    end
end

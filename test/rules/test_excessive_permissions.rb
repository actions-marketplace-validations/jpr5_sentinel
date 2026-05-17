require_relative "../test_helper"

class TestExcessivePermissions < Minitest::Test
    def setup
        @rule = Rules::ExcessivePermissions.new
    end

    def test_flags_contents_write_with_no_write_steps
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              permissions:
                contents: write
              steps:
                - uses: actions/checkout@v4
                - run: npm test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :low, findings.first.severity
        assert_equal "excessive-permissions", findings.first.rule
        assert_match(/contents: write/, findings.first.message)
    end

    def test_safe_when_job_has_git_push
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              permissions:
                contents: write
              steps:
                - uses: actions/checkout@v4
                - run: |
                    git add .
                    git commit -m "update"
                    git push
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_contents_read
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              permissions:
                contents: read
              steps:
                - uses: actions/checkout@v4
                - run: npm test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_no_permissions_block
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - run: npm test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

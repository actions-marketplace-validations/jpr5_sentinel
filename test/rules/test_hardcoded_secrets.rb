require_relative "../test_helper"

class TestHardcodedSecrets < Minitest::Test
    def setup
        @rule = Rules::HardcodedSecrets.new
    end

    def test_flags_aws_access_key
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  run: |
                    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/AWS access key/, findings.first.message)
    end

    def test_flags_github_pat
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Clone
                  run: |
                    git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij@github.com/org/repo
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/GitHub personal access token/, findings.first.message)
    end

    def test_safe_when_using_secrets_expression
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  env:
                    API_KEY: ${{ secrets.API_KEY }}
                  run: echo "deploying"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_line_is_comment
        yaml = <<~YAML
          on: push
          # AKIAIOSFODNN7EXAMPLE is an example key
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_hardcoded_password
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: |
                    password: mysecretpassword123
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_operator findings.length, :>=, 1
        has_password_finding = findings.any? { |f| f.message.match?(/password/i) }
        assert has_password_finding, "Expected a password-related finding"
    end

    def test_safe_password_with_secrets_ref
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: |
                    password: ${{ secrets.DB_PASSWORD }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end
end

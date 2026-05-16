require_relative "../test_helper"

class TestStaticAwsCredentials < Minitest::Test
    def setup
        @rule = Rules::StaticAwsCredentials.new
    end

    def test_flags_static_keys
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: aws-actions/configure-aws-credentials@v4
                  with:
                    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                    aws-region: us-east-1
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "static-aws-credentials", findings.first.rule
    end

    def test_safe_with_oidc_role_to_assume
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: aws-actions/configure-aws-credentials@v4
                  with:
                    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                    role-to-assume: arn:aws:iam::123456789012:role/my-role
                    aws-region: us-east-1
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_action_is_not_configure_aws
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    aws-access-key-id: something
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_even_when_sha_pinned
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300ae5d9a1e72e33b6b189ab18237
                  with:
                    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
                    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
                    aws-region: us-east-1
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end
end

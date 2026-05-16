require_relative "../test_helper"

class TestUnscopedAppToken < Minitest::Test
    def setup
        @rule = Rules::UnscopedAppToken.new
    end

    def test_flags_token_without_permissions
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/create-github-app-token@v1
                  with:
                    app-id: ${{ vars.APP_ID }}
                    private-key: ${{ secrets.APP_KEY }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "unscoped-app-token", findings.first.rule
    end

    def test_safe_with_permission_contents
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/create-github-app-token@v1
                  with:
                    app-id: ${{ vars.APP_ID }}
                    private-key: ${{ secrets.APP_KEY }}
                    permission-contents: write
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_with_multiple_permissions
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/create-github-app-token@v1
                  with:
                    app-id: ${{ vars.APP_ID }}
                    private-key: ${{ secrets.APP_KEY }}
                    permission-contents: write
                    permission-pull-requests: read
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_even_when_sha_pinned
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/create-github-app-token@a0de51f8db146e4c6353ead8c66a8a5e4d1373ff
                  with:
                    app-id: ${{ vars.APP_ID }}
                    private-key: ${{ secrets.APP_KEY }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end
end

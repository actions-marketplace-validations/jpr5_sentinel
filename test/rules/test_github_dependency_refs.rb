require_relative "../test_helper"

class TestGithubDependencyRefs < Minitest::Test
    def setup
        @rule = Rules::GithubDependencyRefs.new
    end

    def wf(run_line)
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: #{run_line}
        YAML
        Workflow.new(filename: "ci.yml", content: yaml)
    end

    # --- Rule metadata ---

    def test_rule_name
        assert_equal "github-dependency-refs", @rule.name
    end

    def test_rule_severity
        assert_equal :medium, @rule.severity
    end

    def test_rule_description
        assert_match(/GitHub.*ref/, @rule.description)
    end

    # --- Detection ---

    def test_flags_npm_install_github_ref
        findings = @rule.check(wf("npm install github:owner/repo#abc123"))
        assert_equal 1, findings.length
        assert_match(/GitHub.*ref/, findings.first.message)
    end

    def test_flags_yarn_add_git_https
        findings = @rule.check(wf("yarn add git+https://github.com/owner/repo"))
        assert_equal 1, findings.length
        assert_match(/GitHub.*ref/, findings.first.message)
    end

    def test_flags_pnpm_add_github_ref
        findings = @rule.check(wf("pnpm add github:owner/repo#main"))
        assert_equal 1, findings.length
    end

    def test_flags_bun_add_github_ref
        findings = @rule.check(wf("bun add github:owner/repo#sha256"))
        assert_equal 1, findings.length
    end

    # --- Safe patterns ---

    def test_safe_npm_install_registry_package
        findings = @rule.check(wf("npm install express"))
        assert_empty findings
    end

    def test_safe_pnpm_install_registry_package
        findings = @rule.check(wf("pnpm install lodash"))
        assert_empty findings
    end

    def test_safe_comment_line
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: |
                    # npm install github:owner/repo#abc123
                    echo "skipped"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Fix message ---

    def test_fix_message
        findings = @rule.check(wf("npm install github:owner/repo#abc123"))
        assert_match(/registry/, findings.first.fix)
    end
end

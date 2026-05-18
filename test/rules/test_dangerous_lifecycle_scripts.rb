require_relative "../test_helper"

class TestDangerousLifecycleScripts < Minitest::Test
    def setup
        @rule = Rules::DangerousLifecycleScripts.new
    end

    def wf_with_secrets(run_line)
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: #{run_line}
                - name: Publish
                  run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        Workflow.new(filename: "ci.yml", content: yaml)
    end

    def wf_no_secrets(run_line)
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: #{run_line}
                - run: npm test
        YAML
        Workflow.new(filename: "ci.yml", content: yaml)
    end

    def test_rule_name
        assert_equal "dangerous-lifecycle-scripts", @rule.name
    end

    def test_rule_severity
        assert_equal :medium, @rule.severity
    end

    # --- Only fires when secrets present ---

    def test_flags_npm_install_with_secrets
        findings = @rule.check(wf_with_secrets("npm install"))
        assert findings.any? { |f| f.message.include?("npm") }
    end

    def test_no_findings_without_secrets
        findings = @rule.check(wf_no_secrets("npm install"))
        assert_empty findings
    end

    # --- Detection with secrets ---

    def test_flags_npm_ci_with_secrets
        findings = @rule.check(wf_with_secrets("npm ci"))
        assert findings.any? { |f| f.message.include?("npm") }
    end

    def test_flags_pnpm_install_with_secrets
        findings = @rule.check(wf_with_secrets("pnpm install"))
        assert findings.any? { |f| f.message.include?("pnpm") }
    end

    def test_flags_yarn_install_with_secrets
        findings = @rule.check(wf_with_secrets("yarn install"))
        assert findings.any? { |f| f.message.include?("yarn") }
    end

    def test_flags_bun_install_with_secrets
        findings = @rule.check(wf_with_secrets("bun install"))
        assert findings.any? { |f| f.message.include?("bun") }
    end

    # --- Safe patterns (even with secrets) ---

    def test_safe_npm_ci_ignore_scripts
        findings = @rule.check(wf_with_secrets("npm ci --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_pnpm_ignore_scripts
        findings = @rule.check(wf_with_secrets("pnpm install --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_bun_no_scripts
        findings = @rule.check(wf_with_secrets("bun install --no-scripts"))
        assert_empty findings
    end

    # --- Comments ---

    def test_skips_comments
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: |
                    # npm install
                    echo "skipped"
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_fix_includes_ignore_scripts
        findings = @rule.check(wf_with_secrets("npm install"))
        assert findings.any? { |f| f.fix.include?("--ignore-scripts") }
    end
end

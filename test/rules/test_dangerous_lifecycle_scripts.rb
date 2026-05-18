require_relative "../test_helper"

class TestDangerousLifecycleScripts < Minitest::Test
    def setup
        @rule = Rules::DangerousLifecycleScripts.new
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
        assert_equal "dangerous-lifecycle-scripts", @rule.name
    end

    def test_rule_severity
        assert_equal :high, @rule.severity
    end

    def test_rule_description
        assert_match(/ignore-scripts/, @rule.description)
    end

    # --- Detection: npm ---

    def test_flags_npm_install
        findings = @rule.check(wf("npm install"))
        assert findings.any? { |f| f.message.include?("npm") && f.message.include?("lifecycle") }
    end

    def test_flags_npm_ci
        findings = @rule.check(wf("npm ci"))
        assert findings.any? { |f| f.message.include?("npm") && f.message.include?("lifecycle") }
    end

    # --- Detection: pnpm ---

    def test_flags_pnpm_install
        findings = @rule.check(wf("pnpm install"))
        assert findings.any? { |f| f.message.include?("pnpm") && f.message.include?("lifecycle") }
    end

    # --- Detection: yarn ---

    def test_flags_yarn_install
        findings = @rule.check(wf("yarn install"))
        assert findings.any? { |f| f.message.include?("yarn") && f.message.include?("lifecycle") }
    end

    # --- Detection: bun ---

    def test_flags_bun_install
        findings = @rule.check(wf("bun install"))
        assert findings.any? { |f| f.message.include?("bun") && f.message.include?("lifecycle") }
    end

    # --- Safe patterns ---

    def test_safe_npm_ci_ignore_scripts
        findings = @rule.check(wf("npm ci --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_npm_install_ignore_scripts
        findings = @rule.check(wf("npm install --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_pnpm_install_ignore_scripts
        findings = @rule.check(wf("pnpm install --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_yarn_install_ignore_scripts
        findings = @rule.check(wf("yarn install --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_bun_install_ignore_scripts
        findings = @rule.check(wf("bun install --ignore-scripts"))
        assert_empty findings
    end

    def test_safe_bun_install_no_scripts
        findings = @rule.check(wf("bun install --no-scripts"))
        assert_empty findings
    end

    # --- Comment skipping ---

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
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Fix message ---

    def test_fix_message_includes_ignore_scripts
        findings = @rule.check(wf("npm install"))
        assert findings.any? { |f| f.fix.include?("--ignore-scripts") }
    end
end

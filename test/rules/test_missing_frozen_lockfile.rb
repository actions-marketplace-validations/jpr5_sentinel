require_relative "../test_helper"

class TestMissingFrozenLockfile < Minitest::Test
    def setup
        @rule = Rules::MissingFrozenLockfile.new
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
        assert_equal "missing-frozen-lockfile", @rule.name
    end

    def test_rule_severity
        assert_equal :medium, @rule.severity
    end

    def test_rule_description
        assert_equal "Package install without lockfile enforcement", @rule.description
    end

    # --- JavaScript/TypeScript: npm ---

    def test_flags_npm_install
        findings = @rule.check(wf("npm install"))
        assert_equal 1, findings.length
        assert_match(/npm install/, findings.first.message)
    end

    def test_safe_npm_ci
        findings = @rule.check(wf("npm ci"))
        assert_empty findings
    end

    def test_safe_npm_install_ci_flag
        findings = @rule.check(wf("npm install --ci"))
        assert_empty findings
    end

    # --- JavaScript/TypeScript: pnpm ---

    def test_flags_pnpm_install
        findings = @rule.check(wf("pnpm install"))
        assert_equal 1, findings.length
        assert_match(/pnpm install/, findings.first.message)
    end

    def test_safe_pnpm_frozen_lockfile
        findings = @rule.check(wf("pnpm install --frozen-lockfile"))
        assert_empty findings
    end

    # --- JavaScript/TypeScript: yarn ---

    def test_flags_yarn_install
        findings = @rule.check(wf("yarn install"))
        assert_equal 1, findings.length
        assert_match(/yarn install/, findings.first.message)
    end

    def test_safe_yarn_frozen_lockfile
        findings = @rule.check(wf("yarn install --frozen-lockfile"))
        assert_empty findings
    end

    def test_safe_yarn_immutable
        findings = @rule.check(wf("yarn install --immutable"))
        assert_empty findings
    end

    # --- JavaScript/TypeScript: bun ---

    def test_flags_bun_install
        findings = @rule.check(wf("bun install"))
        assert_equal 1, findings.length
        assert_match(/bun install/, findings.first.message)
    end

    def test_safe_bun_frozen_lockfile
        findings = @rule.check(wf("bun install --frozen-lockfile"))
        assert_empty findings
    end

    # --- Python: pip ---

    def test_flags_pip_install_package
        findings = @rule.check(wf("pip install requests flask"))
        assert_equal 1, findings.length
        assert_match(/pip install/, findings.first.message)
    end

    def test_flags_pip3_install_package
        findings = @rule.check(wf("pip3 install requests"))
        assert_equal 1, findings.length
    end

    def test_safe_pip_requirements_file
        findings = @rule.check(wf("pip install -r requirements.txt"))
        assert_empty findings
    end

    def test_safe_pip_requirement_long_flag
        findings = @rule.check(wf("pip install --requirement requirements.txt"))
        assert_empty findings
    end

    def test_safe_pip_constraint
        findings = @rule.check(wf("pip install --constraint constraints.txt requests"))
        assert_empty findings
    end

    def test_safe_pip_local_dot
        findings = @rule.check(wf("pip install ."))
        assert_empty findings
    end

    def test_safe_pip_local_editable
        findings = @rule.check(wf("pip install -e ."))
        assert_empty findings
    end

    def test_safe_pip_local_dot_with_extras
        findings = @rule.check(wf("pip install .[dev]"))
        assert_empty findings
    end

    # --- Python: uv pip ---

    def test_flags_uv_pip_install_package
        findings = @rule.check(wf("uv pip install requests"))
        assert_equal 1, findings.length
        assert_match(/pip install/, findings.first.message)
    end

    def test_safe_uv_pip_requirements
        findings = @rule.check(wf("uv pip install -r requirements.txt"))
        assert_empty findings
    end

    # --- Ruby: bundle ---

    def test_flags_bundle_install
        findings = @rule.check(wf("bundle install"))
        assert_equal 1, findings.length
        assert_match(/bundle install/, findings.first.message)
    end

    def test_flags_bare_bundle
        findings = @rule.check(wf("bundle"))
        assert_equal 1, findings.length
    end

    def test_safe_bundle_frozen
        findings = @rule.check(wf("bundle install --frozen"))
        assert_empty findings
    end

    def test_safe_bundle_deployment
        findings = @rule.check(wf("bundle install --deployment"))
        assert_empty findings
    end

    def test_safe_bundle_frozen_env
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Install
                  run: BUNDLE_FROZEN=true bundle install
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_bundle_exec
        findings = @rule.check(wf("bundle exec rspec"))
        assert_empty findings
    end

    # --- Go ---

    def test_flags_go_get
        findings = @rule.check(wf("go get ./..."))
        assert_equal 1, findings.length
        assert_match(/go get/, findings.first.message)
    end

    def test_no_flag_go_mod_download
        findings = @rule.check(wf("go mod download"))
        assert_empty findings
    end

    # --- Rust ---

    def test_flags_cargo_install
        findings = @rule.check(wf("cargo install cargo-audit"))
        assert_equal 1, findings.length
        assert_match(/cargo install/, findings.first.message)
    end

    def test_safe_cargo_install_locked
        findings = @rule.check(wf("cargo install --locked cargo-audit"))
        assert_empty findings
    end

    def test_no_flag_cargo_build
        findings = @rule.check(wf("cargo build --release"))
        assert_empty findings
    end

    # --- PHP ---

    def test_flags_composer_update
        findings = @rule.check(wf("composer update"))
        assert_equal 1, findings.length
        assert_match(/composer update/, findings.first.message)
    end

    def test_no_flag_composer_install
        findings = @rule.check(wf("composer install"))
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

    # --- Fix messages ---

    def test_npm_fix_message
        findings = @rule.check(wf("npm install"))
        assert_match(/npm ci/, findings.first.fix)
    end

    def test_yarn_fix_message
        findings = @rule.check(wf("yarn install"))
        assert_match(/frozen-lockfile.*immutable|immutable.*frozen-lockfile/, findings.first.fix)
    end

    def test_go_get_fix_message
        findings = @rule.check(wf("go get ./..."))
        assert_match(/go mod download/, findings.first.fix)
    end

    def test_composer_update_fix_message
        findings = @rule.check(wf("composer update"))
        assert_match(/composer install/, findings.first.fix)
    end
end

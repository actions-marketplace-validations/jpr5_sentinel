require_relative "../test_helper"

class TestBuildPublishSameJob < Minitest::Test
    def setup
        @rule = Rules::BuildPublishSameJob.new
    end

    def test_flags_npm_install_and_publish_with_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_safe_when_install_and_publish_in_separate_jobs
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm test
            publish:
              runs-on: ubuntu-latest
              needs: build
              steps:
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_pnpm_install_and_publish
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pnpm install
                - run: pnpm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end

    def test_safe_when_no_publish_secrets
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_when_secrets_in_job_level_env
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              env:
                NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
              steps:
                - run: npm install
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end

    def test_flags_python_pip_install_and_twine_upload_with_pypi_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pip install -r requirements.txt
                - run: python setup.py sdist bdist_wheel
                - run: twine upload dist/*
                  env:
                    PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_flags_ruby_bundle_install_and_gem_push_with_api_key
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: bundle install
                - run: rake build
                - run: gem push pkg/*.gem
                  env:
                    GEM_HOST_API_KEY: ${{ secrets.RUBYGEMS_API_KEY }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_flags_rust_cargo_build_and_publish_with_registry_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: cargo build --release
                - run: cargo publish
                  env:
                    CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    # --ignore-scripts mitigation tests (per-package-manager coverage)

    def test_safe_when_pnpm_install_has_ignore_scripts
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pnpm install --frozen-lockfile --ignore-scripts
                - run: pnpm publish --no-git-checks
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "publish-release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when pnpm install has --ignore-scripts"
    end

    def test_safe_when_npm_install_has_ignore_scripts
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when npm install has --ignore-scripts"
    end

    def test_safe_when_npm_ci_has_ignore_scripts
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm ci --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when npm ci has --ignore-scripts"
    end

    def test_safe_when_yarn_install_has_ignore_scripts
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: yarn install --ignore-scripts
                - run: yarn publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when yarn install has --ignore-scripts"
    end

    def test_still_flags_when_only_some_installs_have_ignore_scripts
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install --ignore-scripts
                - run: pnpm install
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "should still fire when not ALL install commands have --ignore-scripts"
    end

    def test_safe_when_install_has_ignore_scripts_equals_true
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install --ignore-scripts=true
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when npm install has --ignore-scripts=true"
    end

    def test_safe_with_multiline_install_command
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - name: Install dependencies
                  run: |
                    pnpm install \\
                      --frozen-lockfile \\
                      --ignore-scripts
                - run: pnpm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when multiline install command has --ignore-scripts"
    end

    def test_safe_when_job_level_secrets_but_all_installs_mitigated
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              env:
                NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
              steps:
                - run: pnpm install --frozen-lockfile --ignore-scripts
                - run: pnpm run build
                - run: pnpm publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "should not fire when job-level secrets but all installs mitigated"
    end

    # --- per-command-level --ignore-scripts edge cases ---

    def test_fires_when_one_install_mitigated_but_another_is_not_in_multiline
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install
                    pip install x --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_fires_when_ignore_scripts_on_non_install_command
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install
                    echo "use --ignore-scripts next time"
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_safe_when_ignore_scripts_via_line_continuation
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    pnpm install \\
                      --frozen-lockfile \\
                      --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_multiple_installs_all_mitigated
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install --ignore-scripts
                    pnpm install --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # --- Bug fix: --ignore-scripts=false substring match ---

    def test_fires_when_ignore_scripts_equals_false
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install --ignore-scripts=false
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "--ignore-scripts=false explicitly disables the mitigation and should still fire"
    end

    def test_fires_when_no_scripts_equals_false
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install --no-scripts=false
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "--no-scripts=false explicitly disables the mitigation and should still fire"
    end

    # --- Bug fix: inline shell comments treated as mitigation ---

    def test_fires_when_ignore_scripts_only_in_trailing_comment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install # use --ignore-scripts later
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "--ignore-scripts in a trailing comment should not count as mitigation"
    end

    def test_fires_when_ignore_scripts_in_comment_of_multiline_block
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install # TODO: add --ignore-scripts
                    npm run build
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "--ignore-scripts in an inline comment should not count as mitigation"
    end

    def test_safe_when_ignore_scripts_in_actual_command_not_comment
        # Ensure stripping comments doesn't break real mitigations
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install --ignore-scripts # safe install
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "real --ignore-scripts before a comment should still count as mitigated"
    end

    # --- Bug fix: strip_shell_comment backslash-escape and #-delimiter edge cases ---

    def test_fires_when_ignore_scripts_in_comment_after_escaped_quote
        # Bug A: backslash-escaped quotes inside a string confuse quote tracking.
        # The \" should NOT end the double-quote context, so `# --ignore-scripts`
        # is still a trailing comment and must not count as mitigation.
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install "foo\\"bar" # --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "escaped quote should not toggle quote state; --ignore-scripts in comment must not count"
    end

    def test_safe_when_hash_in_git_tag_spec_not_treated_as_comment
        # Bug B: npm install user/repo#v1.0.0 --ignore-scripts
        # The # in the package spec is NOT a comment (no preceding whitespace).
        # strip_shell_comment must preserve --ignore-scripts after the #tag.
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install user/repo#v1.0.0 --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "hash in git tag spec (no preceding whitespace) should not be treated as comment delimiter"
    end

    def test_safe_when_hash_inside_quoted_string_not_treated_as_comment
        # A # inside quotes is not a comment — should not strip it
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install --ignore-scripts "pkg#1.0"
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings, "hash inside quotes should not be treated as comment start"
    end

    def test_fires_when_ignore_scripts_in_comment_after_single_quote_backslash
        # POSIX shell: backslash inside single quotes is LITERAL, not an escape.
        # The canonical shell idiom 'foo'\''bar' uses '\'' to splice a literal
        # single-quote into a single-quoted string.  The \' must NOT be treated
        # as an escaped quote (skipping a character) because that desynchronizes
        # the parser's quote tracking.
        #
        # Here the run line is:
        #   npm install 'foo'\''bar' # --ignore-scripts
        # After correct parsing: 'foo' ends the first single-quoted segment,
        # \' is a literal escaped quote in unquoted context, then 'bar' is
        # another single-quoted segment, then ` # --ignore-scripts` is a
        # trailing comment.  The rule should fire because --ignore-scripts
        # appears only inside a comment.
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    npm install 'foo'\\''bar' # --ignore-scripts
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "backslash inside single quotes is literal in POSIX shell; --ignore-scripts in trailing comment must not count"
    end
end

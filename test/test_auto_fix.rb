require_relative "test_helper"

class MockShaResolver
    def resolve(_owner_action, _tag)
        "a]b4ffde65f46336ab88eb53be808477a3936bae11"[2..]
    end
end

class TestAutoFix < Minitest::Test
    def test_can_fix_unpinned_actions
        f = Finding.new(rule: "unpinned-actions", severity: :critical, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_can_fix_shell_injection_expr
        f = Finding.new(rule: "shell-injection-expr", severity: :critical, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_can_fix_missing_persist_credentials
        f = Finding.new(rule: "missing-persist-credentials", severity: :high, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_can_fix_missing_permissions_basic
        f = Finding.new(rule: "missing-permissions", severity: :medium, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_cannot_fix_dangerous_triggers
        f = Finding.new(rule: "dangerous-triggers", severity: :critical, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        refute AutoFix.can_fix?(f)
    end

    def test_fix_unpinned_action_produces_sha
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "unpinned-actions",
            severity: :medium,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/checkout@v4",
            message: "Not pinned",
            fix: "Pin to SHA"
        )
        result = AutoFix.apply(finding, yaml, sha_resolver: MockShaResolver.new)
        assert_includes result, "b4ffde65f46336ab88eb53be808477a3936bae11"
        assert_includes result, "# v4"
    end

    def test_fix_unpinned_action_subpath
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/cache/restore@v4
        YAML
        finding = Finding.new(
            rule: "unpinned-actions",
            severity: :medium,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/cache/restore@v4",
            message: "Not pinned",
            fix: "Pin to SHA"
        )
        result = AutoFix.apply(finding, yaml, sha_resolver: MockShaResolver.new)
        assert_includes result, "actions/cache/restore@b4ffde65f46336ab88eb53be808477a3936bae11"
    end

    def test_fix_shell_injection_expr_moves_to_env
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 9,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "env:"
        assert_includes result, "PR_TITLE:"
        assert_includes result, "$PR_TITLE"
        # The expression should remain in the env mapping
        assert_includes result, "${{ github.event.pull_request.title }}"
    end

    def test_fix_persist_credentials_adds_flag
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-persist-credentials",
            severity: :high,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/checkout@v4",
            message: "Missing persist-credentials",
            fix: "Add persist-credentials: false"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "persist-credentials: false"
    end

    def test_fix_persist_credentials_existing_with_block
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: main
        YAML
        finding = Finding.new(
            rule: "missing-persist-credentials",
            severity: :high,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/checkout@v4",
            message: "Missing persist-credentials",
            fix: "Add persist-credentials: false"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "persist-credentials: false"
        assert_includes result, "ref: main"
    end

    def test_fix_shell_injection_with_existing_env_block
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  env:
                    FOO: bar
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 11,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "PR_TITLE:"
        assert_includes result, "FOO: bar"
        assert_includes result, "$PR_TITLE"
    end

    def test_apply_returns_content_for_unknown_rule
        yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        finding = Finding.new(
            rule: "unknown-rule",
            severity: :low,
            file: "ci.yml",
            line: 1,
            code: "",
            message: "",
            fix: ""
        )
        result = AutoFix.apply(finding, yaml)
        assert_equal yaml, result
    end

    # --- workflow-dispatch-injection ---

    def test_can_fix_workflow_dispatch_injection
        f = Finding.new(rule: "workflow-dispatch-injection", severity: :high, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_fix_dispatch_injection_moves_to_env
        yaml = <<~YAML
          name: Deploy
          on:
            workflow_dispatch:
              inputs:
                version:
                  description: Version to deploy
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  run: |
                    echo "Deploying ${{ inputs.version }}"
        YAML
        finding = Finding.new(
            rule: "workflow-dispatch-injection",
            severity: :high,
            file: "deploy.yml",
            line: 13,
            code: 'echo "Deploying ${{ inputs.version }}"',
            message: "Dispatch input injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "env:"
        assert_includes result, "INPUT_VERSION:"
        assert_includes result, "${{ inputs.version }}"
        assert_includes result, "$INPUT_VERSION"
        # The run block should use the env var, not the expression
        refute_includes result.split("run: |").last, "${{ inputs.version }}"
    end

    def test_fix_dispatch_injection_github_event_inputs
        yaml = <<~YAML
          name: Deploy
          on: workflow_dispatch
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  run: |
                    echo "${{ github.event.inputs.target }}"
        YAML
        finding = Finding.new(
            rule: "workflow-dispatch-injection",
            severity: :high,
            file: "deploy.yml",
            line: 9,
            code: 'echo "${{ github.event.inputs.target }}"',
            message: "Dispatch input injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "INPUT_TARGET:"
        assert_includes result, "${{ github.event.inputs.target }}"
        assert_includes result, "$INPUT_TARGET"
    end

    # --- missing-permissions ---

    def test_can_fix_missing_permissions
        f = Finding.new(rule: "missing-permissions", severity: :medium, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_fix_missing_permissions_adds_block
        yaml = <<~YAML
          name: CI
          on: [push, pull_request]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-permissions",
            severity: :medium,
            file: "ci.yml",
            line: 1,
            code: "",
            message: "No permissions block",
            fix: "Add permissions"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "permissions:"
        assert_includes result, "  contents: read"
        # Permissions should come before jobs:
        perm_pos = result.index("permissions:")
        jobs_pos = result.index("jobs:")
        assert perm_pos < jobs_pos, "permissions: should appear before jobs:"
    end

    def test_fix_missing_permissions_with_multiline_on
        yaml = <<~YAML
          name: CI
          on:
            push:
              branches: [main]
            pull_request:
              branches: [main]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-permissions",
            severity: :medium,
            file: "ci.yml",
            line: 1,
            code: "",
            message: "No permissions block",
            fix: "Add permissions"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "permissions:"
        assert_includes result, "  contents: read"
        perm_pos = result.index("permissions:")
        jobs_pos = result.index("jobs:")
        on_pos = result.index("on:")
        assert perm_pos > on_pos, "permissions: should appear after on:"
        assert perm_pos < jobs_pos, "permissions: should appear before jobs:"
    end

    def test_fix_missing_permissions_skips_if_already_present
        yaml = <<~YAML
          name: CI
          on: push
          permissions:
            contents: write
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-permissions",
            severity: :medium,
            file: "ci.yml",
            line: 1,
            code: "",
            message: "No permissions block",
            fix: "Add permissions"
        )
        result = AutoFix.apply(finding, yaml)
        # Should not add a second permissions block
        assert_equal 1, result.scan(/^permissions:/).length
    end

    # --- missing-timeouts ---

    def test_can_fix_missing_timeouts
        f = Finding.new(rule: "missing-timeouts", severity: :medium, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        assert AutoFix.can_fix?(f)
    end

    def test_fix_missing_timeouts_adds_timeout
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-timeouts",
            severity: :medium,
            file: "ci.yml",
            line: 5,
            code: "runs-on: ubuntu-latest",
            message: "Job 'build' missing timeout",
            fix: "Add timeout-minutes"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "timeout-minutes: 30"
        # timeout should be at the same indent as runs-on
        lines = result.lines
        runs_on_line = lines.find { |l| l.include?("runs-on:") }
        timeout_line = lines.find { |l| l.include?("timeout-minutes:") }
        assert_equal runs_on_line[/^(\s*)/, 1], timeout_line[/^(\s*)/, 1]
    end

    def test_fix_missing_timeouts_skips_if_already_present
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              timeout-minutes: 15
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-timeouts",
            severity: :medium,
            file: "ci.yml",
            line: 5,
            code: "runs-on: ubuntu-latest",
            message: "Job 'build' missing timeout",
            fix: "Add timeout-minutes"
        )
        result = AutoFix.apply(finding, yaml)
        # Should not add a second timeout
        assert_equal 1, result.scan(/timeout-minutes:/).length
    end

    def test_fix_missing_timeouts_finds_runs_on_from_job_line
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        # Finding points to the job name line, not runs-on directly
        finding = Finding.new(
            rule: "missing-timeouts",
            severity: :medium,
            file: "ci.yml",
            line: 4,
            code: "build:",
            message: "Job 'build' missing timeout",
            fix: "Add timeout-minutes"
        )
        result = AutoFix.apply(finding, yaml)
        assert_includes result, "timeout-minutes: 30"
    end

    # --- Bug fix regression tests ---

    # Bug 1: New env var entry should match existing entry indentation,
    # not blindly use env_indent + 4 spaces
    def test_existing_env_block_new_entry_matches_indent
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  env:
                    FOO: bar
                    BAZ: qux
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 12,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)

        # Extract indent of FOO and PR_TITLE lines
        lines = result.lines
        foo_line = lines.find { |l| l.include?("FOO: bar") }
        pr_title_line = lines.find { |l| l.include?("PR_TITLE:") }
        assert foo_line, "FOO: bar should still exist"
        assert pr_title_line, "PR_TITLE: should be added"

        foo_indent = foo_line[/^(\s*)/, 1]
        pr_title_indent = pr_title_line[/^(\s*)/, 1]
        assert_equal foo_indent, pr_title_indent,
            "New env entry should match existing entry indent (got #{pr_title_indent.length} vs #{foo_indent.length})"
    end

    # Bug 2: Should merge into existing env: block, not create a duplicate
    def test_existing_env_block_no_duplicate
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  env:
                    FOO: bar
                  run: |
                    echo "${{ github.event.pull_request.title }}"
        YAML
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 11,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)

        # Count env: occurrences at the step level (not in env var values)
        env_block_count = result.lines.count { |l| l =~ /^\s+env:\s*$/ }
        assert_equal 1, env_block_count,
            "Should have exactly 1 env: block, not #{env_block_count}"

        # Both FOO and PR_TITLE should be present
        assert_includes result, "FOO: bar"
        assert_includes result, "PR_TITLE:"
    end

    # Bug 3: Expression must actually be replaced in the run: block content
    def test_expression_replaced_in_run_block
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo "${{ github.event.pull_request.title }}"
                    echo "${{github.event.pull_request.body}}"
        YAML
        finding_title = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 9,
            code: 'echo "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding_title, yaml)

        # The run: block should use $PR_TITLE, not the expression
        run_section = result.split(/^\s+run:\s*\|\s*$/).last
        assert_includes run_section, "$PR_TITLE"
        refute_match(/\$\{\{\s*github\.event\.pull_request\.title\s*\}\}/, run_section)

        # Also test with no-space variant
        finding_body = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 10,
            code: 'echo "${{github.event.pull_request.body}}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result2 = AutoFix.apply(finding_body, yaml)
        run_section2 = result2.split(/^\s+run:\s*\|\s*$/).last
        assert_includes run_section2, "$PR_BODY"
        refute_match(/\$\{\{.*github\.event\.pull_request\.body.*\}\}/, run_section2)
    end

    # Bug 4: Expression in with: block should NOT trigger shell injection fix
    def test_expression_in_with_block_not_fixed
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Comment
                  uses: some/action@v1
                  with:
                    body: "${{ github.event.pull_request.title }}"
                - name: Build
                  run: echo "hello"
        YAML
        # Finding points to line 10 (the with: body line), which contains
        # the expression but is NOT inside a run: block
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 10,
            code: 'body: "${{ github.event.pull_request.title }}"',
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)

        # The fixer should NOT add an env block to the wrong step
        # The output should be unchanged since the expression is not in a run: block
        assert_equal yaml, result,
            "Expression in with: block should not be modified by shell injection fixer"
    end

    # --- YAML validation gate ---

    def test_fix_produces_valid_yaml
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-persist-credentials",
            severity: :high,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/checkout@v4",
            message: "Missing persist-credentials",
            fix: "Add persist-credentials: false"
        )
        result = AutoFix.apply(finding, yaml)
        # The result should be different from the original (fix was applied)
        refute_equal yaml, result
        # And the result must parse as valid YAML
        assert YAML.safe_load(result), "Fixed output should be valid YAML"
    end

    def test_invalid_yaml_fix_returns_original
        # Craft a scenario where a broken fix would produce invalid YAML.
        # We stub AutoFix to return broken YAML from the internal fixer,
        # but the validation gate should catch it and return the original.
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        finding = Finding.new(
            rule: "missing-persist-credentials",
            severity: :high,
            file: "ci.yml",
            line: 7,
            code: "uses: actions/checkout@v4",
            message: "Missing persist-credentials",
            fix: "Add persist-credentials: false"
        )

        # Temporarily replace fix_persist_credentials to return broken YAML
        AutoFix.define_singleton_method(:fix_persist_credentials_original,
            AutoFix.method(:fix_persist_credentials))

        AutoFix.define_singleton_method(:fix_persist_credentials) do |lines, f|
            # Return YAML with a syntax error (tab character in indentation)
            "name: CI\n\ton: push\n  invalid:\n    - :\n"
        end

        stderr_output = StringIO.new
        original_stderr = $stderr
        $stderr = stderr_output

        begin
            result = AutoFix.apply(finding, yaml)
            # The validation gate should reject the broken fix and return original
            assert_equal yaml, result,
                "When fix produces invalid YAML, original content should be returned"
            # Verify a warning was emitted to stderr
            assert_includes stderr_output.string, "AutoFix: generated invalid YAML",
                "Should log a warning about invalid YAML"
        ensure
            $stderr = original_stderr
            # Restore original method
            AutoFix.define_singleton_method(:fix_persist_credentials,
                AutoFix.method(:fix_persist_credentials_original))
            # Clean up the temporary method
            class << AutoFix
                remove_method :fix_persist_credentials_original if method_defined?(:fix_persist_credentials_original)
            end
        end
    end

    # Bug 5: Single-quoted expression should use double quotes in replacement
    def test_single_quoted_expression_uses_double_quotes
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Greet
                  run: |
                    echo '${{ github.event.pull_request.title }}'
        YAML
        finding = Finding.new(
            rule: "shell-injection-expr",
            severity: :critical,
            file: "ci.yml",
            line: 9,
            code: "echo '${{ github.event.pull_request.title }}'",
            message: "Shell injection risk",
            fix: "Move to env block"
        )
        result = AutoFix.apply(finding, yaml)

        # env var should be added
        assert_includes result, "PR_TITLE:"

        # The run block should NOT have single-quoted $PR_TITLE
        # (bash doesn't expand vars in single quotes)
        run_section = result.split(/^\s+run:\s*\|\s*$/).last
        refute_includes run_section, "'$PR_TITLE'",
            "Single-quoted $VAR won't expand in bash - should use double quotes"

        # Should have double-quoted replacement
        assert_includes run_section, '"$PR_TITLE"',
            "Expression in single quotes should be replaced with double-quoted var"
    end
end

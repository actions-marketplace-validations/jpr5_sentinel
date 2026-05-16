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
end

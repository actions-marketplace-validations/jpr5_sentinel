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

    def test_cannot_fix_missing_permissions
        f = Finding.new(rule: "missing-permissions", severity: :medium, file: "ci.yml", line: 1, code: "", message: "", fix: "")
        refute AutoFix.can_fix?(f)
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
end

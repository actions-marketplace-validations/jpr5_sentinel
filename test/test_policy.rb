require_relative "test_helper"
require_relative "../lib/policy"
require "tmpdir"
require "fileutils"

class TestPolicy < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-policy-test")
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def test_loads_valid_config
        path = write_config(<<~YAML)
          severity: high
          rules:
            missing-timeouts: medium
          ignore:
            - "vendor/**"
        YAML

        policy = Policy.new(path)
        assert policy.loaded?
        assert_empty policy.errors
    end

    def test_returns_correct_min_severity
        path = write_config("severity: medium")
        policy = Policy.new(path)
        assert_equal :medium, policy.min_severity
    end

    def test_default_min_severity_when_not_set
        path = write_config("rules: {}")
        policy = Policy.new(path)
        assert_equal :low, policy.min_severity
    end

    def test_rule_severity_override
        path = write_config(<<~YAML)
          rules:
            missing-timeouts: critical
        YAML

        policy = Policy.new(path)
        assert_equal :critical, policy.rule_severity("missing-timeouts")
    end

    def test_rule_severity_off
        path = write_config(<<~YAML)
          rules:
            overly-broad-triggers: off
        YAML

        policy = Policy.new(path)
        assert_equal :off, policy.rule_severity("overly-broad-triggers")
    end

    def test_rule_severity_returns_nil_for_unknown
        path = write_config("rules: {}")
        policy = Policy.new(path)
        assert_nil policy.rule_severity("nonexistent-rule")
    end

    def test_ignored_files_match_glob
        path = write_config(<<~YAML)
          ignore:
            - "vendor/**"
            - ".github/workflows/dependabot-*.yml"
        YAML

        policy = Policy.new(path)
        assert policy.ignored?(".github/workflows/dependabot-auto.yml")
        refute policy.ignored?(".github/workflows/ci.yml")
    end

    def test_exceptions_match_by_rule_and_file
        path = write_config(<<~YAML)
          exceptions:
            - rule: credential-window
              file: publish-release.yml
              reason: "Intentional pattern"
        YAML

        policy = Policy.new(path)

        matching = Finding.new(rule: "credential-window", severity: :medium, file: "publish-release.yml", line: 1, code: nil, message: "test", fix: nil)
        assert policy.excepted?(matching)

        non_matching = Finding.new(rule: "credential-window", severity: :medium, file: "other.yml", line: 1, code: nil, message: "test", fix: nil)
        refute policy.excepted?(non_matching)

        wrong_rule = Finding.new(rule: "unpinned-actions", severity: :critical, file: "publish-release.yml", line: 1, code: nil, message: "test", fix: nil)
        refute policy.excepted?(wrong_rule)
    end

    def test_exceptions_without_file_match_all_files
        path = write_config(<<~YAML)
          exceptions:
            - rule: missing-timeouts
              reason: "Not needed for our workflows"
        YAML

        policy = Policy.new(path)

        f1 = Finding.new(rule: "missing-timeouts", severity: :medium, file: "ci.yml", line: 1, code: nil, message: "test", fix: nil)
        f2 = Finding.new(rule: "missing-timeouts", severity: :medium, file: "deploy.yml", line: 1, code: nil, message: "test", fix: nil)
        assert policy.excepted?(f1)
        assert policy.excepted?(f2)
    end

    def test_exceptions_require_reason_field
        path = write_config(<<~YAML)
          exceptions:
            - rule: credential-window
              file: publish-release.yml
        YAML

        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("missing required 'reason' field") }
    end

    def test_unknown_top_level_keys_produce_errors
        path = write_config(<<~YAML)
          severity: high
          bogus_key: true
          another_bad: false
        YAML

        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("Unknown key 'bogus_key'") }
        assert policy.errors.any? { |e| e.include?("Unknown key 'another_bad'") }
    end

    def test_unknown_rule_names_produce_errors
        path = write_config(<<~YAML)
          rules:
            totally-fake-rule: high
        YAML

        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("Unknown rule 'totally-fake-rule'") }
    end

    def test_invalid_severity_values_produce_errors
        path = write_config("severity: banana")
        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("Invalid severity 'banana'") }
    end

    def test_invalid_rule_severity_values_produce_errors
        path = write_config(<<~YAML)
          rules:
            missing-timeouts: banana
        YAML

        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("Invalid severity 'banana' for rule 'missing-timeouts'") }
    end

    def test_empty_policy_when_no_path
        policy = Policy.new
        refute policy.loaded?
        assert_empty policy.errors
        assert_equal :low, policy.min_severity
    end

    def test_empty_policy_when_file_missing
        policy = Policy.new("/nonexistent/path/.sentinel-ci.yml")
        refute policy.loaded?
        assert_empty policy.errors
    end

    def test_yaml_syntax_error_produces_error
        path = write_config("{ invalid yaml: [")
        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("YAML syntax error") }
    end

    def test_own_sentinel_config_loads_without_errors
        config_path = File.join(File.dirname(__FILE__), "..", ".sentinel-ci.yml")
        if File.exist?(config_path)
            policy = Policy.new(config_path)
            assert policy.loaded?, "Our own .sentinel-ci.yml should load"
            assert_empty policy.errors, "Our own .sentinel-ci.yml should have no errors: #{policy.errors.inspect}"
        else
            skip "No .sentinel-ci.yml in repo root"
        end
    end

    def test_required_policies
        path = write_config(<<~YAML)
          policy:
            require:
              - sha-pinned-actions
              - permissions-block
        YAML

        policy = Policy.new(path)
        assert_equal ["sha-pinned-actions", "permissions-block"], policy.required_policies
    end

    def test_recommended_policies
        path = write_config(<<~YAML)
          policy:
            recommend:
              - timeout-minutes
        YAML

        policy = Policy.new(path)
        assert_equal ["timeout-minutes"], policy.recommended_policies
    end

    def test_unknown_policy_keys_produce_errors
        path = write_config(<<~YAML)
          policy:
            require:
              - foo
            bogus: true
        YAML

        policy = Policy.new(path)
        assert policy.errors.any? { |e| e.include?("Unknown key 'bogus' in policy section") }
    end

    private

    def write_config(content)
        path = File.join(@tmpdir, ".sentinel-ci.yml")
        File.write(path, content)
        path
    end
end

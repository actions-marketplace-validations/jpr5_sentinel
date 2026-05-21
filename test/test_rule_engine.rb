require_relative "test_helper"

class TestRuleEngine < Minitest::Test
    def setup
        @engine = RuleEngine.new
    end

    def test_loads_all_rules
        # 31 rule files (everything in lib/rules/ except base.rb)
        assert_equal 31, @engine.rules.length,
            "Expected 31 rules, got #{@engine.rules.length}: #{@engine.rules.map(&:name).sort.join(', ')}"
    end

    def test_all_rules_have_name
        @engine.rules.each do |rule|
            refute_nil rule.name, "Rule #{rule.class} should have a name"
            assert_kind_of String, rule.name
            refute_empty rule.name
        end
    end

    def test_all_rules_have_severity
        @engine.rules.each do |rule|
            assert_includes Finding::SEVERITIES, rule.severity,
                "Rule #{rule.name} has invalid severity: #{rule.severity}"
        end
    end

    def test_all_rules_have_description
        @engine.rules.each do |rule|
            refute_nil rule.description, "Rule #{rule.name} should have a description"
            assert_kind_of String, rule.description
            refute_empty rule.description
        end
    end

    def test_rules_sorted_by_severity_critical_first
        severities = @engine.rules.map(&:severity)
        severity_indices = severities.map { |s| Finding::SEVERITY_ORDER[s] || 99 }

        severity_indices.each_cons(2) do |a, b|
            assert a <= b, "Rules should be sorted by severity (critical first), found #{a} before #{b}"
        end
    end

    def test_scan_returns_array_of_findings
        wf = Workflow.new(
            filename: "ci.yml",
            content: <<~YAML
                name: CI
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
            YAML
        )

        findings = @engine.scan(wf)
        assert_kind_of Array, findings
        findings.each do |f|
            assert_kind_of Finding, f
        end
    end

    def test_scan_returns_sorted_findings
        wf = Workflow.new(
            filename: "ci.yml",
            content: <<~YAML
                name: CI
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v4
                      - run: echo "${{ github.event.pull_request.title }}"
            YAML
        )

        findings = @engine.scan(wf)
        return if findings.length <= 1

        severity_indices = findings.map { |f| Finding::SEVERITY_ORDER[f.severity] || 99 }
        severity_indices.each_cons(2) do |a, b|
            assert a <= b, "Findings should be sorted by severity"
        end
    end

    def test_scan_isolates_rule_errors
        wf = Workflow.new(
            filename: "ci.yml",
            content: <<~YAML
                name: CI
                on: push
                permissions:
                  contents: read
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo hi
            YAML
        )

        # Create a crashing rule
        crashing_rule = Object.new
        crashing_rule.define_singleton_method(:name) { "crashing-rule" }
        crashing_rule.define_singleton_method(:severity) { :critical }
        crashing_rule.define_singleton_method(:check) { |_wf| raise "Boom!" }

        # Insert crashing rule into the engine
        original_rules = @engine.rules.dup
        @engine.rules.unshift(crashing_rule)

        # scan should not raise even though one rule crashes
        findings = nil
        assert_silent_or_stderr do
            findings = @engine.scan(wf)
        end

        assert_kind_of Array, findings
        # Other rules should still have produced findings
        crashing_findings = findings.select { |f| f.rule == "crashing-rule" }
        assert_empty crashing_findings, "Crashing rule should not produce findings"
    ensure
        # Restore original rules
        @engine.instance_variable_set(:@rules, original_rules) if original_rules
    end

    def test_scan_clean_workflow_produces_minimal_findings
        wf = Workflow.new(
            filename: "ci.yml",
            content: <<~YAML
                name: CI
                on: push
                permissions:
                  contents: read
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    timeout-minutes: 30
                    steps:
                      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
                        with:
                          persist-credentials: false
                      - run: echo "hello"
            YAML
        )

        findings = @engine.scan(wf)
        # A well-constructed workflow should have very few findings
        # (possibly missing-frozen-lockfile or similar, but no critical/high)
        critical_high = findings.select { |f| f.severity == :critical || f.severity == :high }
        assert_empty critical_high,
            "Clean workflow should have no critical/high findings, got: #{critical_high.map(&:rule)}"
    end

    def test_each_rule_returns_array_from_check
        wf = Workflow.new(
            filename: "ci.yml",
            content: <<~YAML
                name: CI
                on: push
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo hi
            YAML
        )

        @engine.rules.each do |rule|
            result = rule.check(wf)
            assert_kind_of Array, result,
                "Rule #{rule.name}.check should return an Array, got #{result.class}"
        end
    end

    def test_unique_rule_names
        names = @engine.rules.map(&:name)
        assert_equal names.length, names.uniq.length,
            "Rule names should be unique. Duplicates: #{names.select { |n| names.count(n) > 1 }.uniq}"
    end

    private

    def assert_silent_or_stderr
        # Allow stderr output (rule error messages) but don't fail on it
        original_stderr = $stderr
        $stderr = StringIO.new
        yield
    ensure
        $stderr = original_stderr
    end
end

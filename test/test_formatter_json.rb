require_relative "test_helper"
require "json"

class TestFormatterJson < Minitest::Test
    def setup
        @formatter = Formatter::Json.new
    end

    def test_output_is_valid_json
        output = @formatter.format(repo: "owner/repo", workflow_count: 2, findings: [])
        parsed = JSON.parse(output)
        assert_kind_of Hash, parsed
    end

    def test_empty_findings_produces_empty_array
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        parsed = JSON.parse(output)
        assert_equal [], parsed["findings"]
    end

    def test_empty_findings_summary_all_zeros
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        parsed = JSON.parse(output)
        summary = parsed["summary"]
        Finding::SEVERITIES.each do |sev|
            assert_equal 0, summary[sev.to_s], "#{sev} count should be 0 for empty findings"
        end
    end

    def test_repo_name_in_output
        output = @formatter.format(repo: "my-org/my-repo", workflow_count: 1, findings: [])
        parsed = JSON.parse(output)
        assert_equal "my-org/my-repo", parsed["repo"]
    end

    def test_workflow_count_in_output
        output = @formatter.format(repo: "owner/repo", workflow_count: 7, findings: [])
        parsed = JSON.parse(output)
        assert_equal 7, parsed["workflows"]
    end

    def test_findings_array_matches_input
        findings = [
            Finding.new(rule: "rule-a", severity: :critical, file: "ci.yml", line: 10, code: "uses: foo@v1", message: "msg A", fix: "fix A"),
            Finding.new(rule: "rule-b", severity: :low, file: "deploy.yml", line: 20, code: "run: bad", message: "msg B", fix: "fix B"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 2, findings: findings)
        parsed = JSON.parse(output)

        assert_equal 2, parsed["findings"].length

        # Findings are sorted by severity, so critical should be first
        first = parsed["findings"][0]
        assert_equal "rule-a", first["rule"]
        assert_equal "critical", first["severity"]
        assert_equal "ci.yml", first["file"]
        assert_equal 10, first["line"]
        assert_equal "msg A", first["message"]
        assert_equal "fix A", first["fix"]
    end

    def test_findings_sorted_by_severity
        findings = [
            Finding.new(rule: "low-rule", severity: :low, file: "a.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "crit-rule", severity: :critical, file: "b.yml", line: 2, code: "", message: "m", fix: "f"),
            Finding.new(rule: "med-rule", severity: :medium, file: "c.yml", line: 3, code: "", message: "m", fix: "f"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)
        severities = parsed["findings"].map { |f| f["severity"] }

        assert_equal "critical", severities[0]
        assert_equal "medium", severities[1]
        assert_equal "low", severities[2]
    end

    def test_summary_counts_are_correct
        findings = [
            Finding.new(rule: "r1", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r2", severity: :critical, file: "a.yml", line: 2, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r3", severity: :high, file: "a.yml", line: 3, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r4", severity: :medium, file: "a.yml", line: 4, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r5", severity: :medium, file: "a.yml", line: 5, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r6", severity: :medium, file: "a.yml", line: 6, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r7", severity: :low, file: "a.yml", line: 7, code: "", message: "m", fix: "f"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)
        summary = parsed["summary"]

        assert_equal 2, summary["critical"]
        assert_equal 1, summary["high"]
        assert_equal 3, summary["medium"]
        assert_equal 1, summary["low"]
    end

    def test_finding_to_h_fields_present
        findings = [
            Finding.new(rule: "test-rule", severity: :high, file: "ci.yml", line: 5, code: "code here", message: "the message", fix: "the fix"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)
        f = parsed["findings"][0]

        %w[rule severity file line code message fix].each do |key|
            assert f.key?(key), "Finding should have '#{key}' key"
        end
    end

    def test_severity_serialized_as_string
        findings = [
            Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: "f"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)

        assert_kind_of String, parsed["findings"][0]["severity"]
        assert_equal "critical", parsed["findings"][0]["severity"]
    end

    def test_single_finding
        findings = [
            Finding.new(rule: "solo-rule", severity: :medium, file: "ci.yml", line: 42, code: "echo bad", message: "Found issue", fix: "Fix it"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)

        assert_equal 1, parsed["findings"].length
        assert_equal "solo-rule", parsed["findings"][0]["rule"]
    end

    def test_nil_fix_serialized
        findings = [
            Finding.new(rule: "r", severity: :low, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        parsed = JSON.parse(output)

        assert_nil parsed["findings"][0]["fix"]
    end
end

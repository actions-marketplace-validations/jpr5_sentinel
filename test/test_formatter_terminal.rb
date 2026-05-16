require_relative "test_helper"

class TestFormatterTerminal < Minitest::Test
    def setup
        @formatter = Formatter::Terminal.new
    end

    def test_empty_findings_produces_no_findings_message
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        assert_includes output, "No findings."
    end

    def test_empty_findings_does_not_include_summary_line
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        refute_includes output, "Summary:"
    end

    def test_repo_name_in_output
        output = @formatter.format(repo: "owner/my-repo", workflow_count: 3, findings: [])
        assert_includes output, "owner/my-repo"
    end

    def test_workflow_count_in_output
        output = @formatter.format(repo: "owner/repo", workflow_count: 5, findings: [])
        assert_includes output, "5 workflows"
    end

    def test_findings_sorted_by_severity_in_output
        findings = [
            Finding.new(rule: "low-rule", severity: :low, file: "a.yml", line: 1, code: "", message: "low msg", fix: nil),
            Finding.new(rule: "crit-rule", severity: :critical, file: "b.yml", line: 2, code: "", message: "crit msg", fix: nil),
            Finding.new(rule: "med-rule", severity: :medium, file: "c.yml", line: 3, code: "", message: "med msg", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        crit_pos = output.index("CRITICAL")
        med_pos = output.index("MEDIUM")
        low_pos = output.index("LOW")

        refute_nil crit_pos, "Output should contain CRITICAL"
        refute_nil med_pos, "Output should contain MEDIUM"
        refute_nil low_pos, "Output should contain LOW"
        assert crit_pos < med_pos, "CRITICAL should appear before MEDIUM"
        assert med_pos < low_pos, "MEDIUM should appear before LOW"
    end

    def test_severity_colors_applied_critical
        findings = [
            Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "\e[31m", "Critical findings should use red ANSI color"
    end

    def test_severity_colors_applied_high
        findings = [
            Finding.new(rule: "r", severity: :high, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "\e[33m", "High findings should use yellow ANSI color"
    end

    def test_severity_colors_applied_medium
        findings = [
            Finding.new(rule: "r", severity: :medium, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "\e[36m", "Medium findings should use cyan ANSI color"
    end

    def test_severity_colors_applied_low
        findings = [
            Finding.new(rule: "r", severity: :low, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "\e[90m", "Low findings should use dim ANSI color"
    end

    def test_reset_code_present
        findings = [
            Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "\e[0m", "Output should contain ANSI reset code"
    end

    def test_summary_line_shows_correct_counts
        findings = [
            Finding.new(rule: "r1", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
            Finding.new(rule: "r2", severity: :critical, file: "a.yml", line: 2, code: "", message: "m", fix: nil),
            Finding.new(rule: "r3", severity: :high, file: "a.yml", line: 3, code: "", message: "m", fix: nil),
            Finding.new(rule: "r4", severity: :low, file: "a.yml", line: 4, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "Summary:"
        assert_includes output, "2 critical"
        assert_includes output, "1 high"
        assert_includes output, "1 low"
        # medium count is 0, should not appear
        refute_includes output, "0 medium"
    end

    def test_fix_line_shown_when_fix_present
        findings = [
            Finding.new(rule: "r", severity: :high, file: "a.yml", line: 1, code: "", message: "msg", fix: "Do this to fix it"),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "Fix: Do this to fix it"
    end

    def test_fix_line_not_shown_when_fix_nil
        findings = [
            Finding.new(rule: "r", severity: :high, file: "a.yml", line: 1, code: "", message: "msg", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        refute_includes output, "Fix:"
    end

    def test_finding_displays_file_and_line
        findings = [
            Finding.new(rule: "test-rule", severity: :medium, file: "deploy.yml", line: 42, code: "", message: "msg", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "deploy.yml:42"
    end

    def test_finding_displays_message
        findings = [
            Finding.new(rule: "r", severity: :medium, file: "a.yml", line: 1, code: "", message: "This is the finding message", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "This is the finding message"
    end

    def test_finding_displays_rule_name
        findings = [
            Finding.new(rule: "my-custom-rule", severity: :medium, file: "a.yml", line: 1, code: "", message: "m", fix: nil),
        ]

        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        assert_includes output, "my-custom-rule"
    end

    def test_bold_formatting_used
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        assert_includes output, "\e[1m", "Output should contain bold ANSI code"
    end

    def test_green_color_for_no_findings
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        assert_includes output, "\e[32m", "No findings message should use green ANSI color"
    end
end

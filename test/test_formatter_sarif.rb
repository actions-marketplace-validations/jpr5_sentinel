require_relative "test_helper"
require "json"

class TestFormatterSarif < Minitest::Test
    def setup
        @formatter = Formatter::Sarif.new
    end

    def test_output_is_valid_json
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        parsed = JSON.parse(output)
        assert_kind_of Hash, parsed
    end

    def test_correct_schema_and_version
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        sarif = JSON.parse(output)
        assert_equal "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", sarif["$schema"]
        assert_equal "2.1.0", sarif["version"]
    end

    def test_tool_driver_metadata
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        sarif = JSON.parse(output)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert_equal "sentinel", driver["name"]
        assert_equal "https://sentinel.copilotkit.dev", driver["informationUri"]
        assert_equal Sentinel::VERSION, driver["version"]
    end

    def test_empty_findings_produce_empty_results
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: [])
        sarif = JSON.parse(output)
        assert_equal [], sarif["runs"][0]["results"]
        assert_equal [], sarif["runs"][0]["tool"]["driver"]["rules"]
    end

    def test_findings_map_to_results
        findings = [
            Finding.new(rule: "unpinned-actions", severity: :critical, file: "ci.yml", line: 10, code: "", message: "Action is unpinned", fix: "Pin to SHA")
        ]
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        sarif = JSON.parse(output)
        results = sarif["runs"][0]["results"]
        assert_equal 1, results.length
        assert_equal "unpinned-actions", results[0]["ruleId"]
        assert_equal "error", results[0]["level"]
        assert_equal "Action is unpinned. Fix: Pin to SHA", results[0]["message"]["text"]
    end

    def test_file_paths_include_workflow_prefix
        findings = [
            Finding.new(rule: "test-rule", severity: :high, file: "deploy.yml", line: 5, code: "", message: "msg", fix: "fix")
        ]
        output = @formatter.format(repo: "owner/repo", workflow_count: 1, findings: findings)
        sarif = JSON.parse(output)
        location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert_equal ".github/workflows/deploy.yml", location["artifactLocation"]["uri"]
        assert_equal "%SRCROOT%", location["artifactLocation"]["uriBaseId"]
    end

    def test_critical_maps_to_error
        findings = [Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: "f")]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        assert_equal "error", sarif["runs"][0]["results"][0]["level"]
    end

    def test_high_maps_to_error
        findings = [Finding.new(rule: "r", severity: :high, file: "a.yml", line: 1, code: "", message: "m", fix: "f")]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        assert_equal "error", sarif["runs"][0]["results"][0]["level"]
    end

    def test_medium_maps_to_warning
        findings = [Finding.new(rule: "r", severity: :medium, file: "a.yml", line: 1, code: "", message: "m", fix: "f")]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        assert_equal "warning", sarif["runs"][0]["results"][0]["level"]
    end

    def test_low_maps_to_note
        findings = [Finding.new(rule: "r", severity: :low, file: "a.yml", line: 1, code: "", message: "m", fix: "f")]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        assert_equal "note", sarif["runs"][0]["results"][0]["level"]
    end

    def test_line_zero_clamped_to_one
        findings = [Finding.new(rule: "r", severity: :low, file: "a.yml", line: 0, code: "", message: "m", fix: "f")]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert_equal 1, region["startLine"]
    end

    def test_rules_deduplicated_by_rule_id
        findings = [
            Finding.new(rule: "unpinned-actions", severity: :critical, file: "a.yml", line: 1, code: "", message: "m1", fix: "f1"),
            Finding.new(rule: "unpinned-actions", severity: :critical, file: "a.yml", line: 5, code: "", message: "m2", fix: "f2"),
            Finding.new(rule: "shell-injection", severity: :high, file: "b.yml", line: 3, code: "", message: "m3", fix: "f3"),
        ]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 2, findings: findings))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert_equal 2, rules.length
        assert_equal ["unpinned-actions", "shell-injection"], rules.map { |r| r["id"] }
    end

    def test_rules_level_matches_severity
        findings = [
            Finding.new(rule: "r-crit", severity: :critical, file: "a.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r-med", severity: :medium, file: "a.yml", line: 2, code: "", message: "m", fix: "f"),
        ]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        crit_rule = rules.find { |r| r["id"] == "r-crit" }
        med_rule = rules.find { |r| r["id"] == "r-med" }
        assert_equal "error", crit_rule["defaultConfiguration"]["level"]
        assert_equal "warning", med_rule["defaultConfiguration"]["level"]
    end

    def test_results_sorted_by_severity
        findings = [
            Finding.new(rule: "r-low", severity: :low, file: "a.yml", line: 1, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r-crit", severity: :critical, file: "a.yml", line: 2, code: "", message: "m", fix: "f"),
            Finding.new(rule: "r-med", severity: :medium, file: "a.yml", line: 3, code: "", message: "m", fix: "f"),
        ]
        sarif = JSON.parse(@formatter.format(repo: "o/r", workflow_count: 1, findings: findings))
        levels = sarif["runs"][0]["results"].map { |r| r["level"] }
        assert_equal ["error", "warning", "note"], levels
    end
end

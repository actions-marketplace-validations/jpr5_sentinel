require_relative "test_helper"

class TestFinding < Minitest::Test
    def test_severity_ordering_critical_before_high
        critical = Finding.new(rule: "r1", severity: :critical, file: "a.yml", line: 1, code: "", message: "", fix: "")
        high = Finding.new(rule: "r2", severity: :high, file: "a.yml", line: 1, code: "", message: "", fix: "")
        assert_equal(-1, critical <=> high)
    end

    def test_severity_ordering_high_before_medium
        high = Finding.new(rule: "r1", severity: :high, file: "a.yml", line: 1, code: "", message: "", fix: "")
        medium = Finding.new(rule: "r2", severity: :medium, file: "a.yml", line: 1, code: "", message: "", fix: "")
        assert_equal(-1, high <=> medium)
    end

    def test_severity_ordering_medium_before_low
        medium = Finding.new(rule: "r1", severity: :medium, file: "a.yml", line: 1, code: "", message: "", fix: "")
        low = Finding.new(rule: "r2", severity: :low, file: "a.yml", line: 1, code: "", message: "", fix: "")
        assert_equal(-1, medium <=> low)
    end

    def test_severity_ordering_equal
        a = Finding.new(rule: "r1", severity: :high, file: "a.yml", line: 1, code: "", message: "", fix: "")
        b = Finding.new(rule: "r2", severity: :high, file: "a.yml", line: 2, code: "", message: "", fix: "")
        assert_equal(0, a <=> b)
    end

    def test_severity_ordering_sort
        findings = [
            Finding.new(rule: "r1", severity: :low, file: "a.yml", line: 1, code: "", message: "", fix: ""),
            Finding.new(rule: "r2", severity: :critical, file: "a.yml", line: 2, code: "", message: "", fix: ""),
            Finding.new(rule: "r3", severity: :medium, file: "a.yml", line: 3, code: "", message: "", fix: ""),
            Finding.new(rule: "r4", severity: :high, file: "a.yml", line: 4, code: "", message: "", fix: ""),
        ]
        sorted = findings.sort
        assert_equal [:critical, :high, :medium, :low], sorted.map(&:severity)
    end

    def test_critical_predicate
        f = Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "", fix: "")
        assert f.critical?
        refute f.high?
        refute f.medium?
        refute f.low?
    end

    def test_high_predicate
        f = Finding.new(rule: "r", severity: :high, file: "a.yml", line: 1, code: "", message: "", fix: "")
        refute f.critical?
        assert f.high?
        refute f.medium?
        refute f.low?
    end

    def test_medium_predicate
        f = Finding.new(rule: "r", severity: :medium, file: "a.yml", line: 1, code: "", message: "", fix: "")
        refute f.critical?
        refute f.high?
        assert f.medium?
        refute f.low?
    end

    def test_low_predicate
        f = Finding.new(rule: "r", severity: :low, file: "a.yml", line: 1, code: "", message: "", fix: "")
        refute f.critical?
        refute f.high?
        refute f.medium?
        assert f.low?
    end

    def test_to_h_keys
        f = Finding.new(rule: "test-rule", severity: :high, file: "ci.yml", line: 5, code: "uses: foo", message: "msg", fix: "fix it")
        h = f.to_h
        assert_equal "test-rule", h[:rule]
        assert_equal "high", h[:severity]
        assert_equal "ci.yml", h[:file]
        assert_equal 5, h[:line]
        assert_equal "uses: foo", h[:code]
        assert_equal "msg", h[:message]
        assert_equal "fix it", h[:fix]
    end

    def test_to_h_severity_is_string
        f = Finding.new(rule: "r", severity: :critical, file: "a.yml", line: 1, code: "", message: "", fix: "")
        assert_kind_of String, f.to_h[:severity]
    end
end

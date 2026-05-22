require_relative "test_helper"

class TestAnnotateEnv < Minitest::Test
    # Test the env-var reading logic used in action/annotate.rb line 245.
    # GitHub Actions passes docker action inputs as INPUT_<name> with dashes
    # preserved (only spaces become underscores). The annotate script must
    # read INPUT_FAIL-ON-FINDINGS (hyphen) first, falling back to the
    # underscore form for reusable-workflow callers.

    def teardown
        ENV.delete("INPUT_FAIL-ON-FINDINGS")
        ENV.delete("INPUT_FAIL_ON_FINDINGS")
    end

    # Extract the ACTUAL expression from annotate.rb so the test exercises
    # production logic, not a copy. This reads annotate.rb, finds the fail_on
    # assignment, and evals it.
    def read_fail_on_from_annotate
        annotate_path = File.expand_path("../../action/annotate.rb", __FILE__)
        source = File.read(annotate_path)

        # Extract the RHS of:  fail_on   = (ENV[...] || ...).downcase == "true"
        match = source.match(/^fail_on\s*=\s*(.+)$/)
        raise "Could not find fail_on assignment in annotate.rb" unless match

        eval(match[1])
    end

    # ── Hyphen form (primary: docker action) ─────────────────────────────────

    def test_hyphen_env_var_false_disables_fail
        ENV.delete("INPUT_FAIL_ON_FINDINGS")
        ENV["INPUT_FAIL-ON-FINDINGS"] = "false"
        refute read_fail_on_from_annotate, "fail_on should be false when INPUT_FAIL-ON-FINDINGS=false"
    end

    def test_hyphen_env_var_true_enables_fail
        ENV.delete("INPUT_FAIL_ON_FINDINGS")
        ENV["INPUT_FAIL-ON-FINDINGS"] = "true"
        assert read_fail_on_from_annotate, "fail_on should be true when INPUT_FAIL-ON-FINDINGS=true"
    end

    # ── Underscore form (fallback: reusable workflow) ────────────────────────

    def test_underscore_env_var_false_disables_fail
        ENV.delete("INPUT_FAIL-ON-FINDINGS")
        ENV["INPUT_FAIL_ON_FINDINGS"] = "false"
        refute read_fail_on_from_annotate, "fail_on should be false when INPUT_FAIL_ON_FINDINGS=false"
    end

    def test_underscore_env_var_true_enables_fail
        ENV.delete("INPUT_FAIL-ON-FINDINGS")
        ENV["INPUT_FAIL_ON_FINDINGS"] = "true"
        assert read_fail_on_from_annotate, "fail_on should be true when INPUT_FAIL_ON_FINDINGS=true"
    end

    # ── Precedence: hyphen wins over underscore ──────────────────────────────

    def test_hyphen_takes_precedence_over_underscore
        ENV["INPUT_FAIL-ON-FINDINGS"] = "false"
        ENV["INPUT_FAIL_ON_FINDINGS"] = "true"
        refute read_fail_on_from_annotate, "hyphen form should take precedence (false wins)"
    end

    # ── Neither set: defaults to true ────────────────────────────────────────

    def test_defaults_to_true_when_neither_set
        ENV.delete("INPUT_FAIL-ON-FINDINGS")
        ENV.delete("INPUT_FAIL_ON_FINDINGS")
        assert read_fail_on_from_annotate, "fail_on should default to true when neither env var is set"
    end
end

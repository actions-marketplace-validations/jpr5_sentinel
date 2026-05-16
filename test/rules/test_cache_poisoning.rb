require_relative "../test_helper"

class TestCachePoisoning < Minitest::Test
    def setup
        @rule = Rules::CachePoisoning.new
    end

    def test_flags_cache_key_with_github_head_ref
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/cache@v3
                  with:
                    path: ~/.cache
                    key: ${{ runner.os }}-${{ github.head_ref }}-cache
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "cache-poisoning", findings.first.rule
        assert_match(/fork-controllable/, findings.first.message)
    end

    def test_safe_with_hashfiles_only
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/cache@v3
                  with:
                    path: node_modules
                    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_cache_key_with_github_ref_on_pull_request
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/cache@v3
                  with:
                    path: ~/.cache
                    key: ${{ runner.os }}-${{ github.ref }}-deps
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_match(/github\.ref/, findings.first.message)
    end

    def test_safe_with_fixed_string_key
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/cache@v3
                  with:
                    path: ~/.cache
                    key: my-project-cache-v1
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

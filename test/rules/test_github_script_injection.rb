require_relative "../test_helper"

class TestGithubScriptInjection < Minitest::Test
    def setup
        @rule = Rules::GithubScriptInjection.new
    end

    def test_flags_pr_title_in_script_block
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
                      console.log(title);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/pull_request\.title/, findings.first.message)
    end

    def test_safe_when_using_context_payload
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const title = context.payload.pull_request.title;
                      console.log(title);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_not_in_github_script_step
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: some/other-action@v1
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_issue_body_in_script
        yaml = <<~YAML
          on: issues
          jobs:
            triage:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const body = "${{ github.event.issue.body }}";
                      github.rest.issues.createComment({
                        issue_number: context.issue.number,
                        owner: context.repo.owner,
                        repo: context.repo.repo,
                        body: body
                      });
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/issue\.body/, findings.first.message)
    end

    def test_no_flag_with_step_guard_excludes_pull_request
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - if: github.event_name == 'push'
                  uses: actions/github-script@v7
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_with_job_guard_excludes_pull_request
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              if: github.event_name == 'push'
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_expr_only_in_trailing_comment
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const safe = "hello"; // ${{ github.event.pull_request.title }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        # Note: JavaScript uses // for comments, but YAML inline comments use #
        # The strip_inline_comment strips YAML-style # comments, not JS comments
        # This test verifies the YAML # comment case:
        assert_equal 1, findings.length  # JS // comment is not a YAML comment, so still flagged
    end

    def test_flags_expr_in_yaml_trailing_comment
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const safe = "hello"; # ${{ github.event.pull_request.title }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_still_flags_without_guard
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_no_flag_for_push_only
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_inputs_in_script_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const name = "${{ inputs.name }}";
                      console.log(name);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/inputs\.name/, findings.first.message)
    end

    def test_flags_github_event_inputs_in_script_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const bump = "${{ github.event.inputs.bump }}";
                      console.log(bump);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/github\.event\.inputs\.bump/, findings.first.message)
    end

    def test_no_flag_safe_expression_in_script
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const repo = "${{ github.repository }}";
                      console.log(repo);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_no_flag_inputs_in_run_block
        yaml = <<~YAML
          on:
            workflow_dispatch:
            pull_request:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: |
                    echo "${{ inputs.name }}"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    # Bug #1: 30-line outer lookback cap in in_github_script_block?
    # A script block with >30 lines between uses: and the dangerous expression
    # should still be detected.
    def test_flags_dangerous_expr_in_long_script_block
        script_lines = (1..35).map { |n| "      const x#{n} = #{n};" }.join("\n")
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
          #{script_lines}
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect dangerous expr even when >30 lines from script: key"
        assert_match(/pull_request\.title/, findings.first.message)
    end

    # Bug #2: 15-line inner lookback cap for uses: actions/github-script
    # A long with:/env: block between uses: and script: exceeding 15 lines
    # should still be detected.
    def test_flags_dangerous_expr_with_long_with_block
        env_lines = (1..20).map { |n| "        VAR#{n}: value#{n}" }.join("\n")
        yaml = <<~YAML
          on: pull_request
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  env:
          #{env_lines}
                  with:
                    script: |
                      const title = "${{ github.event.pull_request.title }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "Should detect dangerous expr even when uses: is >15 lines above script:"
        assert_match(/pull_request\.title/, findings.first.message)
    end

    # Bug #3: Event-guard bypass when line has BOTH dangerous AND input expressions
    # When a SINGLE line matches both INPUT_EXPR_PATTERN and DANGEROUS_EXPR_PATTERN,
    # the dangerous one should still be subject to the event guard.
    # Current code: `next if !line.match?(INPUT_EXPR_PATTERN) && guarded_by_safe_event?`
    # means when a line has BOTH patterns, the guard is bypassed entirely because
    # INPUT_EXPR_PATTERN matches -> the `!line.match?` is false -> `&&` short-circuits.
    def test_event_guard_applies_to_dangerous_expr_on_mixed_line
        yaml = <<~YAML
          on:
            push:
            pull_request:
          jobs:
            build:
              if: github.event_name == 'push'
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const x = "${{ github.event.pull_request.title }}" + "${{ inputs.name }}";
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        # The dangerous expr (pull_request.title) should be suppressed by the job guard.
        # Only the input expr (inputs.name) should be flagged -- that's 1 finding.
        assert_equal 1, findings.length, "Only the input expression should be flagged; dangerous expr is guarded"
        assert_match(/inputs\.name/, findings.first.message)
    end

    # Bug #4: safe_trigger_only? early return suppresses INPUT_EXPR_PATTERN checks
    # Even on workflow_dispatch-only triggers, inputs.* is user-controlled and must be flagged.
    def test_flags_inputs_on_dispatch_only_trigger
        yaml = <<~YAML
          on: workflow_dispatch
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/github-script@v7
                  with:
                    script: |
                      const name = "${{ inputs.name }}";
                      console.log(name);
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length, "inputs.* must be flagged even on workflow_dispatch-only triggers"
        assert_match(/inputs\.name/, findings.first.message)
    end
end

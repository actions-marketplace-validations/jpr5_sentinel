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
                - if: github.event_name != 'pull_request'
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
              if: github.event_name != 'pull_request'
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

    def test_no_flag_expr_in_yaml_trailing_comment
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
        assert_empty findings
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
end

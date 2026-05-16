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
end

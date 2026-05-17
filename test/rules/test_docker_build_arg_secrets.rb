require_relative "../test_helper"

class TestDockerBuildArgSecrets < Minitest::Test
    def setup
        @rule = Rules::DockerBuildArgSecrets.new
    end

    def test_flags_secrets_in_build_args
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker/build-push-action@v5
                  with:
                    build-args: |
                      NPM_TOKEN=${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "docker.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "docker-build-arg-secrets", findings.first.rule
    end

    def test_safe_when_build_args_has_no_secrets
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker/build-push-action@v5
                  with:
                    build-args: |
                      NODE_ENV=production
                      APP_VERSION=1.0.0
        YAML
        wf = Workflow.new(filename: "docker.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_handles_multiline_build_args
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker/build-push-action@v5
                  with:
                    build-args: |
                      NODE_ENV=production
                      API_KEY=${{ secrets.API_KEY }}
                      APP_VERSION=1.0.0
        YAML
        wf = Workflow.new(filename: "docker.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/secrets\./, findings.first.code)
    end

    def test_safe_when_secrets_in_docker_secrets_input
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker/build-push-action@v5
                  with:
                    secrets: |
                      NPM_TOKEN=${{ secrets.NPM_TOKEN }}
                    build-args: |
                      NODE_ENV=production
        YAML
        wf = Workflow.new(filename: "docker.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_does_not_flag_non_secret_build_args
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: docker/build-push-action@v5
                  with:
                    build-args: |
                      COMMIT_SHA=${{ github.sha }}
                      BRANCH=${{ github.ref_name }}
        YAML
        wf = Workflow.new(filename: "docker.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

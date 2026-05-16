require_relative "../test_helper"

class TestMissingEnvProtection < Minitest::Test
    def setup
        @rule = Rules::MissingEnvProtection.new
    end

    def test_flags_npm_publish_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "missing-env-protection", findings.first.rule
    end

    def test_flags_mvn_deploy_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: mvn deploy -P release
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "missing-env-protection", findings.first.rule
    end

    def test_flags_cargo_publish_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: cargo publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "missing-env-protection", findings.first.rule
    end

    def test_safe_when_environment_is_set
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              environment: production
              steps:
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_oidc_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              permissions:
                id-token: write
                contents: read
              steps:
                - run: echo "deploying"
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :medium, findings.first.severity
        assert_equal "missing-env-protection", findings.first.rule
    end

    def test_flags_pnpm_publish_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pnpm publish --no-git-checks
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_twine_upload_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: twine upload dist/*
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_docker_push_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: docker push myimage:latest
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_terraform_apply_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: terraform apply -auto-approve
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_dotnet_nuget_push_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: dotnet nuget push *.nupkg
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_gradlew_publish_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: ./gradlew publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_poetry_publish_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: poetry publish --build
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_flags_fly_deploy_without_environment
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: fly deploy
        YAML
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
    end

    def test_safe_no_publish_commands
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end
end

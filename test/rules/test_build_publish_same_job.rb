require_relative "../test_helper"

class TestBuildPublishSameJob < Minitest::Test
    def setup
        @rule = Rules::BuildPublishSameJob.new
    end

    def test_flags_npm_install_and_publish_with_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_safe_when_install_and_publish_in_separate_jobs
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm test
            publish:
              runs-on: ubuntu-latest
              needs: build
              steps:
                - run: npm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_pnpm_install_and_publish
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pnpm install
                - run: pnpm publish
                  env:
                    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end

    def test_safe_when_no_publish_secrets
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: npm install
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_when_secrets_in_job_level_env
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              env:
                NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
              steps:
                - run: npm install
                - run: npm publish
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
    end

    def test_flags_python_pip_install_and_twine_upload_with_pypi_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: pip install -r requirements.txt
                - run: python setup.py sdist bdist_wheel
                - run: twine upload dist/*
                  env:
                    PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_flags_ruby_bundle_install_and_gem_push_with_api_key
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: bundle install
                - run: rake build
                - run: gem push pkg/*.gem
                  env:
                    GEM_HOST_API_KEY: ${{ secrets.RUBYGEMS_API_KEY }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end

    def test_flags_rust_cargo_build_and_publish_with_registry_token
        yaml = <<~YAML
          on: push
          jobs:
            release:
              runs-on: ubuntu-latest
              steps:
                - run: cargo build --release
                - run: cargo publish
                  env:
                    CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        YAML
        wf = Workflow.new(filename: "release.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :high, findings.first.severity
        assert_equal "build-publish-same-job", findings.first.rule
    end
end

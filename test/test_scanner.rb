require_relative "test_helper"
require "tmpdir"
require "fileutils"

class TestScanner < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-test")
        @workflows_dir = File.join(@tmpdir, ".github", "workflows")
        FileUtils.mkdir_p(@workflows_dir)
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def test_scan_finds_unpinned_actions
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    persist-credentials: false
        YAML

        # Also add dependabot config to avoid that finding
        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        findings = result[:findings]
        unpinned = findings.select { |f| f.rule == "unpinned-actions" }
        assert_equal 1, unpinned.length
    end

    def test_scan_counts_workflows
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_workflow("deploy.yml", <<~YAML)
          name: Deploy
          on: push
          permissions:
            contents: read
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: echo deploy
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        assert_equal 2, result[:workflow_count]
    end

    def test_scan_severity_filter
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: pnpm/action-setup@v4
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new

        # Only critical findings
        scanner = Scanner.new(client: client, formatter: formatter, min_severity: :critical)
        result = scanner.scan("test-repo")
        findings = result[:findings]
        refute_empty findings, "severity filter test must produce findings to be meaningful"
        findings.each do |f|
            assert_equal :critical, f.severity
        end
    end

    def test_scan_produces_output
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        refute_nil result[:output]
        assert_kind_of String, result[:output]
    end

    def test_scan_adds_missing_dependabot_finding
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        # No dependabot config
        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        dependabot_findings = result[:findings].select { |f| f.rule == "missing-dependabot" }
        assert_equal 1, dependabot_findings.length
    end

    def test_scan_no_dependabot_finding_when_configured
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        dependabot_findings = result[:findings].select { |f| f.rule == "missing-dependabot" }
        assert_empty dependabot_findings
    end

    def test_scan_adds_missing_zizmor_finding
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        zizmor_findings = result[:findings].select { |f| f.rule == "missing-zizmor" }
        assert_equal 1, zizmor_findings.length
    end

    def test_scan_terminal_formatter
        write_workflow("ci.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Terminal.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        assert_includes result[:output], "test-repo"
    end

    def test_scan_empty_workflow_directory
        # No workflows written — just dependabot to isolate
        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        assert_equal 0, result[:workflow_count]
        workflow_findings = result[:findings].reject { |f|
            %w[missing-dependabot missing-zizmor].include?(f.rule)
        }
        assert_empty workflow_findings
    end

    def test_scan_malformed_yaml_does_not_crash
        write_workflow("valid.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_workflow("malformed.yml", <<~YAML)
          name: Bad
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "unterminated
                  {{: invalid yaml here :::
                  - [broken
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)

        # Should not raise
        result = scanner.scan("test-repo")
        assert_kind_of Hash, result
        assert_equal 2, result[:workflow_count]
    end

    def test_scan_directory_with_no_workflows_dir
        # Create a tmpdir without .github/workflows/
        empty_dir = Dir.mktmpdir("sentinel-empty")
        begin
            # Create .github but not workflows
            FileUtils.mkdir_p(File.join(empty_dir, ".github"))
            # Add dependabot to avoid that finding
            File.write(File.join(empty_dir, ".github", "dependabot.yml"), <<~YAML)
              version: 2
              updates:
                - package-ecosystem: github-actions
                  directory: /
                  schedule:
                    interval: weekly
            YAML

            client = LocalClient.new(empty_dir)
            formatter = Formatter::Json.new
            scanner = Scanner.new(client: client, formatter: formatter)
            result = scanner.scan("test-repo")

            assert_equal 0, result[:workflow_count]
        ensure
            FileUtils.rm_rf(empty_dir)
        end
    end

    def test_scan_completely_empty_directory
        empty_dir = Dir.mktmpdir("sentinel-totally-empty")
        begin
            client = LocalClient.new(empty_dir)
            formatter = Formatter::Json.new
            scanner = Scanner.new(client: client, formatter: formatter)
            result = scanner.scan("test-repo")

            assert_equal 0, result[:workflow_count]
            assert_kind_of Array, result[:findings]
        ensure
            FileUtils.rm_rf(empty_dir)
        end
    end

    def test_scan_only_yaml_extension_files
        # Write a .txt file in workflows dir — should be ignored
        File.write(File.join(@workflows_dir, "not-a-workflow.txt"), "just text")

        write_workflow("real.yml", <<~YAML)
          name: CI
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML

        write_dependabot

        client = LocalClient.new(@tmpdir)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter)
        result = scanner.scan("test-repo")

        assert_equal 1, result[:workflow_count]
    end

    private

    def write_workflow(name, content)
        File.write(File.join(@workflows_dir, name), content)
    end

    def write_dependabot
        dependabot_dir = File.join(@tmpdir, ".github")
        FileUtils.mkdir_p(dependabot_dir)
        File.write(File.join(dependabot_dir, "dependabot.yml"), <<~YAML)
          version: 2
          updates:
            - package-ecosystem: github-actions
              directory: /
              schedule:
                interval: weekly
        YAML
    end
end

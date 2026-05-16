require_relative "test_helper"

class TestWorkflow < Minitest::Test
    def test_parse_valid_yaml
        yaml = <<~YAML
          name: CI
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        refute wf.parse_error?
        assert_equal "CI", wf.data["name"]
    end

    def test_parse_error_graceful
        yaml = "{{invalid yaml"
        wf = Workflow.new(filename: "bad.yml", content: yaml)
        assert wf.parse_error?
        assert_equal({}, wf.data)
    end

    def test_triggers_with_on_key
        yaml = <<~YAML
          on:
            push:
              branches: [main]
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        triggers = wf.triggers
        assert triggers.key?("push")
    end

    def test_triggers_handles_true_key
        # Ruby YAML parses bare `on:` as the boolean true key
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        # on: push parses as {true => "push"} or {"on" => "push"} depending on context
        # The triggers method handles both
        triggers = wf.triggers
        refute_nil triggers
    end

    def test_jobs_accessor
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
            test:
              runs-on: ubuntu-latest
              steps:
                - run: echo test
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        assert_equal %w[build test], wf.jobs.keys.sort
    end

    def test_steps_accessor
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo step1
                - run: echo step2
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        steps = wf.steps("build")
        assert_equal 2, steps.length
    end

    def test_permissions_workflow_level
        yaml = <<~YAML
          on: push
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        perms = wf.permissions(scope: :workflow)
        assert_equal({"contents" => "read"}, perms)
    end

    def test_permissions_job_level
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              permissions:
                packages: write
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        job = wf.jobs["build"]
        perms = wf.permissions(scope: :job, job: job)
        assert_equal({"packages" => "write"}, perms)
    end

    def test_line_of_returns_correct_line
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        line = wf.line_of(/actions\/checkout/)
        assert_equal 6, line
    end

    def test_line_of_returns_nil_when_not_found
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hi
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        assert_nil wf.line_of(/nonexistent/)
    end

    def test_lines_of_returns_all_matches
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - uses: actions/setup-node@v4
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        lines = wf.lines_of(/uses:/)
        assert_equal 3, lines.length
    end

    def test_line_content_returns_correct_content
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hello
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        content = wf.line_content(6)
        assert_match(/run: echo hello/, content)
    end

    def test_uses_actions_extracts_references
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                - uses: actions/setup-node@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        actions = wf.uses_actions
        assert_equal 2, actions.length
        assert_equal "actions/checkout@v4", actions[0][:uses]
        assert_equal "actions/setup-node@v4", actions[1][:uses]
    end

    def test_uses_actions_includes_line_numbers
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        actions = wf.uses_actions
        assert_equal 6, actions[0][:line]
    end

    def test_run_blocks_extracts_blocks
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo hello
                - run: echo world
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        blocks = wf.run_blocks
        assert_equal 2, blocks.length
        assert_equal "echo hello", blocks[0][:run]
        assert_equal "echo world", blocks[1][:run]
    end

    def test_raw_lines_accessible
        yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        assert_equal 6, wf.raw_lines.length
    end

    def test_filename_accessible
        yaml = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        wf = Workflow.new(filename: "deploy.yml", content: yaml)
        assert_equal "deploy.yml", wf.filename
    end

    def test_empty_yaml
        wf = Workflow.new(filename: "empty.yml", content: "")
        assert_equal({}, wf.jobs)
        assert_equal({}, wf.triggers)
    end
end

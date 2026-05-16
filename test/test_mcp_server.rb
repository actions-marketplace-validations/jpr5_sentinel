require_relative "test_helper"
require "open3"
require "json"
require "tmpdir"
require "fileutils"

class TestMcpServer < Minitest::Test
    SERVER_CMD = [RbConfig.ruby, File.join(__dir__, "..", "mcp", "server.rb")]

    def setup
        @tmpdir = Dir.mktmpdir("sentinel-mcp-test")
        @workflows_dir = File.join(@tmpdir, ".github", "workflows")
        FileUtils.mkdir_p(@workflows_dir)
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    # --- Protocol tests ---

    def test_initialize_response
        with_server do |stdin, stdout|
            resp = send_request(stdin, stdout, "initialize", {})
            assert_equal "2.0", resp["jsonrpc"]
            assert_equal 1, resp["id"]

            result = resp["result"]
            assert_equal "2024-11-05", result["protocolVersion"]
            assert_equal "sentinel", result["serverInfo"]["name"]
            assert result["serverInfo"]["version"]
            assert result["capabilities"]["tools"]
        end
    end

    def test_tools_list_returns_three_tools
        with_server do |stdin, stdout|
            # Initialize first
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/list", {}, id: 2)

            tools = resp["result"]["tools"]
            assert_equal 3, tools.length

            names = tools.map { |t| t["name"] }
            assert_includes names, "sentinel_scan"
            assert_includes names, "sentinel_deps"
            assert_includes names, "sentinel_fix"
        end
    end

    def test_tools_list_has_input_schemas
        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/list", {}, id: 2)

            tools = resp["result"]["tools"]
            tools.each do |tool|
                schema = tool["inputSchema"]
                assert_equal "object", schema["type"], "#{tool["name"]} should have object schema"
                assert schema["properties"], "#{tool["name"]} should have properties"
                assert_includes schema["required"], "target", "#{tool["name"]} should require target"
            end
        end
    end

    def test_ping_response
        with_server do |stdin, stdout|
            resp = send_request(stdin, stdout, "ping", {})
            assert_equal "2.0", resp["jsonrpc"]
            assert resp["result"]
        end
    end

    def test_unknown_method_returns_error
        with_server do |stdin, stdout|
            resp = send_request(stdin, stdout, "nonexistent/method", {})
            assert resp["error"]
            assert_equal(-32601, resp["error"]["code"])
            assert_includes resp["error"]["message"], "Method not found"
        end
    end

    def test_unknown_tool_returns_error
        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "nonexistent_tool",
                "arguments" => {}
            }, id: 2)

            assert resp["error"]
            assert_equal(-32602, resp["error"]["code"])
            assert_includes resp["error"]["message"], "Unknown tool"
        end
    end

    def test_notifications_initialized_returns_no_response
        with_server do |stdin, stdout|
            # Send initialize first so server is in a known state
            send_request(stdin, stdout, "initialize", {})

            # Send notification (no id means it's a notification, but our protocol
            # uses id anyway -- the key thing is no response for notifications/initialized)
            request = { jsonrpc: "2.0", method: "notifications/initialized" }
            stdin.puts(JSON.generate(request))

            # Send another request to confirm server is still alive
            resp = send_request(stdin, stdout, "ping", {}, id: 3)
            assert_equal 3, resp["id"]
            assert resp["result"]
        end
    end

    # --- Tool execution tests ---

    def test_sentinel_scan_local_path
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
        write_dependabot

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_scan",
                "arguments" => { "target" => @tmpdir }
            }, id: 2)

            assert resp["result"], "Should have a result"
            content = resp["result"]["content"]
            assert content, "Should have content array"
            assert_equal "text", content[0]["type"]

            output = JSON.parse(content[0]["text"])
            assert output["findings"], "Should have findings key"
            assert output["workflows"], "Should have workflows key"
        end
    end

    def test_sentinel_scan_with_severity_filter
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

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_scan",
                "arguments" => { "target" => @tmpdir, "severity" => "critical" }
            }, id: 2)

            content = resp["result"]["content"]
            output = JSON.parse(content[0]["text"])
            findings = output["findings"]

            findings.each do |f|
                assert_equal "critical", f["severity"],
                    "With severity=critical, all findings should be critical but got #{f["severity"]} for #{f["rule"]}"
            end
        end
    end

    def test_sentinel_scan_sarif_format
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

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_scan",
                "arguments" => { "target" => @tmpdir, "format" => "sarif" }
            }, id: 2)

            content = resp["result"]["content"]
            output = JSON.parse(content[0]["text"])
            assert output["$schema"], "SARIF output should have $schema"
            assert output["runs"], "SARIF output should have runs"
        end
    end

    def test_sentinel_deps_local_path
        write_workflow("ci.yml", <<~YAML)
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: pnpm/action-setup@v2
        YAML

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_deps",
                "arguments" => { "target" => @tmpdir }
            }, id: 2)

            content = resp["result"]["content"]
            deps = JSON.parse(content[0]["text"])
            assert_kind_of Array, deps

            repos = deps.map { |d| d["repo"] }
            assert_includes repos, "actions/checkout"
            assert_includes repos, "pnpm/action-setup"
        end
    end

    def test_sentinel_fix_dry_run
        write_workflow("ci.yml", <<~YAML)
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        YAML
        write_dependabot

        original_content = File.read(File.join(@workflows_dir, "ci.yml"))

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_fix",
                "arguments" => { "target" => @tmpdir, "dry_run" => true }
            }, id: 2)

            content = resp["result"]["content"]
            text = content[0]["text"]

            # Should report dry run
            assert_includes text, "Dry run"

            # File should NOT have been modified
            assert_equal original_content, File.read(File.join(@workflows_dir, "ci.yml")),
                "Dry run should not modify files"
        end
    end

    def test_sentinel_fix_applies_changes
        write_workflow("ci.yml", <<~YAML)
            name: CI
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        YAML
        write_dependabot

        original_content = File.read(File.join(@workflows_dir, "ci.yml"))

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_fix",
                "arguments" => { "target" => @tmpdir, "dry_run" => false }
            }, id: 2)

            content = resp["result"]["content"]
            text = content[0]["text"]

            # Should report files fixed
            assert_includes text, "fixed"
        end
    end

    def test_sentinel_fix_requires_local_path
        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_fix",
                "arguments" => { "target" => "owner/repo" }
            }, id: 2)

            assert resp["error"]
            assert_includes resp["error"]["message"], "local path"
        end
    end

    def test_sentinel_fix_no_fixable_findings
        # Clean workflow with no fixable issues
        write_workflow("ci.yml", <<~YAML)
            name: CI
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
                    with:
                      persist-credentials: false
        YAML
        write_dependabot

        with_server do |stdin, stdout|
            send_request(stdin, stdout, "initialize", {})
            resp = send_request(stdin, stdout, "tools/call", {
                "name" => "sentinel_fix",
                "arguments" => { "target" => @tmpdir }
            }, id: 2)

            content = resp["result"]["content"]
            text = content[0]["text"]
            assert_includes text, "No auto-fixable findings"
        end
    end

    # --- Malformed input tests ---

    def test_parse_error_on_invalid_json
        with_server do |stdin, stdout|
            stdin.puts("this is not json")
            resp = JSON.parse(stdout.gets)
            assert resp["error"]
            assert_equal(-32700, resp["error"]["code"])
        end
    end

    private

    def with_server
        stdin, stdout, stderr, wait_thr = Open3.popen3(*SERVER_CMD)
        # Wait for startup message on stderr
        startup = stderr.gets
        assert startup, "Server should print startup message"
        yield(stdin, stdout)
    ensure
        stdin&.close
        stdout&.close
        stderr&.close
        wait_thr&.value
    end

    def send_request(stdin, stdout, method, params = {}, id: 1)
        request = { jsonrpc: "2.0", id: id, method: method, params: params }
        stdin.puts(JSON.generate(request))
        response_line = stdout.gets
        assert response_line, "Server should return a response for method: #{method}"
        JSON.parse(response_line)
    end

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

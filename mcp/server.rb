#!/usr/bin/env ruby

require "json"
$LOAD_PATH.unshift(File.join(__dir__, "..", "lib"))
require "scanner"
require "supply_chain"
require "version"

class McpServer
    def initialize
        @running = true
    end

    def run
        $stderr.puts "Sentinel MCP server v#{Sentinel::VERSION} starting..."
        while @running && (line = $stdin.gets)
            line = line.strip
            next if line.empty?

            begin
                request = JSON.parse(line)
                response = handle(request)
                write_response(response) if response
            rescue JSON::ParserError => e
                write_response(error_response(nil, -32700, "Parse error: #{e.message}"))
            rescue => e
                $stderr.puts "Error: #{e.message}"
                write_response(error_response(request&.dig("id"), -32603, e.message))
            end
        end
    end

    private

    def handle(request)
        id = request["id"]
        method = request["method"]

        case method
        when "initialize"
            result_response(id, {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: "sentinel", version: Sentinel::VERSION }
            })
        when "notifications/initialized"
            nil  # no response for notifications
        when "tools/list"
            result_response(id, { tools: tool_definitions })
        when "tools/call"
            tool_name = request.dig("params", "name")
            args = request.dig("params", "arguments") || {}
            execute_tool(id, tool_name, args)
        when "ping"
            result_response(id, {})
        else
            error_response(id, -32601, "Method not found: #{method}")
        end
    end

    def tool_definitions
        [
            {
                name: "sentinel_scan",
                description: "Scan a GitHub repo or local path for CI/CD security vulnerabilities. Returns findings with severity, rule, file, line, and fix recommendations.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "GitHub repo (owner/repo) or local path" },
                        severity: { type: "string", enum: ["critical", "high", "medium", "low"], description: "Minimum severity threshold (default: low)" },
                        format: { type: "string", enum: ["json", "sarif"], description: "Output format (default: json)" }
                    },
                    required: ["target"]
                }
            },
            {
                name: "sentinel_deps",
                description: "Analyze third-party action dependencies for a repo with risk scoring. Shows which actions you depend on, their maintainers, stars, and risk factors.",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "GitHub repo (owner/repo) or local path" }
                    },
                    required: ["target"]
                }
            },
            {
                name: "sentinel_fix",
                description: "Auto-fix security findings in workflow files. Returns diffs of what would be changed. Supports 6 mechanical fixes (unpinned actions, shell injection, persist-credentials, missing permissions, missing timeouts, workflow dispatch injection).",
                inputSchema: {
                    type: "object",
                    properties: {
                        target: { type: "string", description: "Local path to scan and fix" },
                        dry_run: { type: "boolean", description: "If true, return diffs without writing files (default: true)" }
                    },
                    required: ["target"]
                }
            }
        ]
    end

    def execute_tool(id, tool_name, args)
        case tool_name
        when "sentinel_scan"
            do_scan(id, args)
        when "sentinel_deps"
            do_deps(id, args)
        when "sentinel_fix"
            do_fix(id, args)
        else
            error_response(id, -32602, "Unknown tool: #{tool_name}")
        end
    end

    def do_scan(id, args)
        target = args["target"]
        severity = (args["severity"] || "low").to_sym
        format = args["format"] || "json"

        client = if File.directory?(target)
            LocalClient.new(target)
        else
            token = ENV["GITHUB_TOKEN"]
            if token
                GitHubClient.new(token: token)
            else
                CloneClient.new
            end
        end

        formatter = format == "sarif" ? Formatter::Sarif.new : Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter, min_severity: severity)

        begin
            result = scanner.scan(target)
            text_response(id, result[:output])
        ensure
            client.cleanup if client.respond_to?(:cleanup)
        end
    end

    def do_deps(id, args)
        target = args["target"]
        token = ENV["GITHUB_TOKEN"]

        workflows = if File.directory?(target)
            LocalClient.new(target).fetch_workflows(target).map { |w|
                Workflow.new(filename: w[:filename], content: w[:content])
            }
        else
            client = token ? GitHubClient.new(token: token) : CloneClient.new
            begin
                raw = client.fetch_workflows(target)
                raw.map { |w| Workflow.new(filename: w[:filename], content: w[:content]) }
            ensure
                client.cleanup if client.respond_to?(:cleanup)
            end
        end

        chain = SupplyChain.new(token: token)
        actions = chain.analyze(workflows)
        text_response(id, JSON.pretty_generate(actions))
    end

    def do_fix(id, args)
        target = args["target"]
        dry_run = args.fetch("dry_run", true)

        unless File.directory?(target)
            return error_response(id, -32602, "sentinel_fix requires a local path, not a remote repo")
        end

        # Scan first
        client = LocalClient.new(target)
        formatter = Formatter::Json.new
        scanner = Scanner.new(client: client, formatter: formatter, min_severity: :low)
        result = scanner.scan(target)

        findings = JSON.parse(result[:output])["findings"]
        fixable = findings.select { |f|
            AutoFix.can_fix?(Finding.new(
                rule: f["rule"], severity: f["severity"].to_sym,
                file: f["file"], line: f["line"],
                code: f["code"], message: f["message"], fix: f["fix"]
            ))
        }

        if fixable.empty?
            return text_response(id, "No auto-fixable findings found.")
        end

        # Apply fixes
        sha_resolver = ShaResolver.new
        diffs = []

        fixable.group_by { |f| f["file"] }.each do |file, file_findings|
            path = File.join(target, ".github", "workflows", file)
            next unless File.exist?(path)

            content = File.read(path)
            original = content.dup

            file_findings.sort_by { |f| -(f["line"] || 0) }.each do |raw|
                finding = Finding.new(
                    rule: raw["rule"], severity: raw["severity"].to_sym,
                    file: raw["file"], line: raw["line"],
                    code: raw["code"], message: raw["message"], fix: raw["fix"]
                )
                patched = AutoFix.apply(finding, content, sha_resolver: sha_resolver)
                content = patched if patched && patched != content
            end

            if content != original
                diffs << "--- .github/workflows/#{file}\n+++ .github/workflows/#{file} (fixed)\n#{content}"
                File.write(path, content) unless dry_run
            end
        end

        summary = dry_run ? "Dry run -- #{diffs.length} files would be fixed" : "#{diffs.length} files fixed"
        text_response(id, "#{summary}\n\n#{diffs.join("\n\n")}")
    end

    def result_response(id, result)
        { jsonrpc: "2.0", id: id, result: result }
    end

    def text_response(id, text)
        result_response(id, { content: [{ type: "text", text: text }] })
    end

    def error_response(id, code, message)
        { jsonrpc: "2.0", id: id, error: { code: code, message: message } }
    end

    def write_response(response)
        json = JSON.generate(response)
        $stdout.puts(json)
        $stdout.flush
    end
end

McpServer.new.run if __FILE__ == $0

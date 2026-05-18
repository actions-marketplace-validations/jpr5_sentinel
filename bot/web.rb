#!/usr/bin/env ruby

require "sinatra"
require "json"
require_relative "config"
require_relative "github_app_auth"
require_relative "state"
require_relative "pr_writer"

set :port, ENV["PORT"] || 3000
set :bind, "0.0.0.0"
set :environment, :production

# Landing page
get "/" do
    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head><title>Sentinel Bot</title></head>
    <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
      <h1>&#x1f6e1;&#xfe0f; Sentinel Bot</h1>
      <p>This bot scans popular open-source repos for CI/CD security vulnerabilities
         and opens fix PRs.</p>
      <p><a href="https://sentinel.copilotkit.dev">Learn more</a> &middot;
         <a href="https://github.com/jpr5/sentinel">Source code</a></p>
    </body>
    </html>
    HTML
end

# Opt out -- confirmation page (GET) + action (POST)
get "/opt-out" do
    repo = params["repo"]
    token = params["token"]

    halt 400, "Missing repo parameter" unless repo
    halt 400, "Missing token parameter" unless token
    halt 403, "Invalid or expired token" unless valid_token?(token, repo, "opt-out")

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head><title>Opt Out &mdash; Sentinel</title></head>
    <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
      <h1>&#x1f6e1;&#xfe0f; Opt out of Sentinel</h1>
      <p>This will prevent Sentinel from opening future PRs on <strong>#{escape_html(repo)}</strong>.</p>
      <form method="POST" action="/opt-out">
        <input type="hidden" name="repo" value="#{escape_html(repo)}">
        <input type="hidden" name="token" value="#{escape_html(token)}">
        <button type="submit" style="padding: 10px 20px; font-size: 1rem; cursor: pointer;">Confirm opt-out</button>
      </form>
    </body>
    </html>
    HTML
end

post "/opt-out" do
    repo = params["repo"]
    token = params["token"]

    halt 400, "Missing repo parameter" unless repo
    halt 400, "Missing token parameter" unless token
    halt 403, "Invalid or expired token" unless valid_token?(token, repo, "opt-out")

    state = Bot::State.new
    state.record_opt_out(repo)
    state.save

    consume_token(token)

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head><title>Opted Out &mdash; Sentinel</title></head>
    <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
      <h1>&#x2705; Opted out</h1>
      <p><strong>#{escape_html(repo)}</strong> will not receive future PRs from Sentinel.</p>
      <p>Changed your mind? <a href="https://github.com/jpr5/sentinel/issues">Let us know</a>.</p>
    </body>
    </html>
    HTML
end

# Adopt -- confirmation page (GET) + action (POST)
get "/adopt" do
    repo = params["repo"]
    token_param = params["token"]

    halt 400, "Missing repo parameter" unless repo
    halt 400, "Missing token parameter" unless token_param
    halt 403, "Invalid or expired token" unless valid_token?(token_param, repo, "adopt")

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head><title>Adopt Sentinel &mdash; Sentinel</title></head>
    <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
      <h1>&#x1f6e1;&#xfe0f; Adopt Sentinel</h1>
      <p>This will open a PR adding the Sentinel security scanner to <strong>#{escape_html(repo)}</strong>.</p>
      <form method="POST" action="/adopt">
        <input type="hidden" name="repo" value="#{escape_html(repo)}">
        <input type="hidden" name="token" value="#{escape_html(token_param)}">
        <button type="submit" style="padding: 10px 20px; font-size: 1rem; cursor: pointer;">Confirm adopt</button>
      </form>
    </body>
    </html>
    HTML
end

post "/adopt" do
    repo = params["repo"]
    token_param = params["token"]

    halt 400, "Missing repo parameter" unless repo
    halt 400, "Missing token parameter" unless token_param
    halt 403, "Invalid or expired token" unless valid_token?(token_param, repo, "adopt")

    if ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"]
        auth = Bot::GitHubAppAuth.new
        bot_token = auth.token_for(repo) || ENV["GITHUB_TOKEN"]
    else
        bot_token = ENV["GITHUB_TOKEN"]
    end
    halt 500, "Bot not configured (missing credentials)" unless bot_token

    writer = Bot::PrWriter.new(token: bot_token)

    workflow_content = <<~YAML
    name: Security Scan
    on:
      pull_request:
        paths: ['.github/workflows/**']
      push:
        branches: [main]
        paths: ['.github/workflows/**']

    permissions:
      contents: read

    jobs:
      scan:
        runs-on: ubuntu-latest
        timeout-minutes: 10
        steps:
          - uses: actions/checkout@v4
            with:
              persist-credentials: false
          - uses: jpr5/sentinel@v1
            with:
              severity: high
    YAML

    pr = writer.create_pr(
        repo: repo,
        branch: "sentinel/add-security-scan",
        title: "Add Sentinel CI/CD security scanning",
        body: "## Add Sentinel Security Scanning\n\n" \
              "This PR adds [Sentinel](https://sentinel.copilotkit.dev) to scan your GitHub Actions " \
              "workflows for security vulnerabilities on every PR.\n\n" \
              "**What it does:**\n" \
              "- Scans workflow files for 28 security rules\n" \
              "- Posts inline annotations on PR diffs\n" \
              "- Fails the check if critical or high findings exist\n\n" \
              "**No secrets, no write permissions needed.** Read-only scan.\n\n" \
              "---\n" \
              "<sub>Generated via [Sentinel Bot](https://sentinel.copilotkit.dev)</sub>",
        files: { ".github/workflows/sentinel.yml" => workflow_content },
    )

    consume_token(token_param)

    if pr
        content_type :html
        <<~HTML
        <!DOCTYPE html>
        <html>
        <head><title>PR Created &mdash; Sentinel</title></head>
        <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
          <h1>&#x2705; PR created</h1>
          <p>A pull request has been opened to add Sentinel to <strong>#{escape_html(repo)}</strong>.</p>
          <p><a href="#{pr["html_url"]}">Review the PR &rarr;</a></p>
        </body>
        </html>
        HTML
    else
        halt 500, "Failed to create PR. The repo may not allow forks, or the bot lacks permissions."
    end
end

# Rule explainer index
get "/rules" do
    rules_dir = File.join(File.dirname(__FILE__), "rules")
    rules = Dir[File.join(rules_dir, "*.md")].map { |f| File.basename(f, ".md") }.sort

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Rules — Sentinel</title>
      <style>
        body {
          font-family: -apple-system, system-ui, sans-serif;
          background: #0a0a0f;
          color: #e8e8f0;
          max-width: 720px;
          margin: 50px auto;
          padding: 0 20px;
          line-height: 1.7;
        }
        h1 { color: #ff4444; margin-bottom: 0.5rem; }
        a { color: #ff4444; }
        ul { padding-left: 1.5rem; }
        li { margin: 0.5rem 0; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / rules
      </div>
      <h1>Security Rules</h1>
      <p>Sentinel scans for the following vulnerability patterns:</p>
      <ul>
        #{rules.map { |r| "<li><a href=\"/rules/#{r}\">#{escape_html(r)}</a></li>" }.join("\n        ")}
      </ul>
      <hr style="border-color: #2a2a3a; margin-top: 3rem;">
      <p style="font-size: 0.85rem; color: #8888a0;">
        <a href="https://sentinel.copilotkit.dev">Sentinel</a> — open-source CI/CD security scanner.
        <a href="https://github.com/jpr5/sentinel">Source</a>
      </p>
    </body>
    </html>
    HTML
end

# Rule explainer page
get "/rules/:rule_name" do
    rule = params["rule_name"].gsub(/[^a-z0-9\-]/, "")
    path = File.join(File.dirname(__FILE__), "rules", "#{rule}.md")

    halt 404, "Rule not found" unless File.exist?(path)

    markdown_content = File.read(path)

    content_type :html
    render_markdown_page(rule, markdown_content)
end

# Token management helpers

def valid_token?(token, repo, action)
    state = Bot::State.new
    state.valid_token?(token, repo, action)
end

def consume_token(token)
    state = Bot::State.new
    state.consume_token(token)
    state.save
end

def escape_html(text)
    text.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;")
end

def markdown_to_html(markdown)
    lines = markdown.lines
    html = ""
    in_code_block = false
    in_list = false
    paragraph = ""

    flush_paragraph = -> {
        unless paragraph.strip.empty?
            html += "<p>#{inline_format(paragraph.strip)}</p>\n"
        end
        paragraph = ""
    }

    lines.each do |line|
        line = line.chomp

        # Fenced code blocks
        if line.match?(/\A```/)
            if in_code_block
                html += "</code></pre>\n"
                in_code_block = false
            else
                flush_paragraph.call
                if in_list
                    html += "</ul>\n"
                    in_list = false
                end
                lang = line.sub(/\A```/, "").strip
                html += "<pre><code>"
                in_code_block = true
            end
            next
        end

        if in_code_block
            html += escape_html(line) + "\n"
            next
        end

        # Blank line
        if line.strip.empty?
            flush_paragraph.call
            if in_list
                html += "</ul>\n"
                in_list = false
            end
            next
        end

        # Headers
        if line.match?(/\A##\s/)
            flush_paragraph.call
            if in_list
                html += "</ul>\n"
                in_list = false
            end
            html += "<h2>#{inline_format(line.sub(/\A##\s+/, ""))}</h2>\n"
            next
        end

        if line.match?(/\A#\s/)
            flush_paragraph.call
            if in_list
                html += "</ul>\n"
                in_list = false
            end
            html += "<h1>#{inline_format(line.sub(/\A#\s+/, ""))}</h1>\n"
            next
        end

        # List items
        if line.match?(/\A- /)
            flush_paragraph.call
            unless in_list
                html += "<ul>\n"
                in_list = true
            end
            html += "<li>#{inline_format(line.sub(/\A- /, ""))}</li>\n"
            next
        end

        # Continuation of paragraph
        paragraph += " " unless paragraph.empty?
        paragraph += line
    end

    flush_paragraph.call
    if in_list
        html += "</ul>\n"
    end
    if in_code_block
        html += "</code></pre>\n"
    end

    html
end

def inline_format(text)
    text = escape_html(text)
    # Bold
    text = text.gsub(/\*\*(.+?)\*\*/, '<strong>\1</strong>')
    # Inline code
    text = text.gsub(/`([^`]+)`/, '<code>\1</code>')
    # Links
    text = text.gsub(/\[([^\]]+)\]\(([^)]+)\)/, '<a href="\2">\1</a>')
    text
end

def render_markdown_page(rule, markdown)
    html = markdown_to_html(markdown)

    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>#{escape_html(rule)} — Sentinel</title>
      <style>
        body {
          font-family: -apple-system, system-ui, sans-serif;
          background: #0a0a0f;
          color: #e8e8f0;
          max-width: 720px;
          margin: 50px auto;
          padding: 0 20px;
          line-height: 1.7;
        }
        h1 { color: #ff4444; margin-bottom: 0.5rem; }
        h2 { color: #e8e8f0; margin-top: 2rem; border-bottom: 1px solid #2a2a3a; padding-bottom: 0.5rem; }
        code { font-family: "JetBrains Mono", monospace; background: #16161f; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
        pre { background: #16161f; border: 1px solid #2a2a3a; border-radius: 8px; padding: 1rem; overflow-x: auto; }
        pre code { background: none; padding: 0; }
        a { color: #ff4444; }
        ul, ol { padding-left: 1.5rem; }
        li { margin: 0.3rem 0; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / <a href="/rules">rules</a> / #{escape_html(rule)}
      </div>
      #{html}
      <hr style="border-color: #2a2a3a; margin-top: 3rem;">
      <p style="font-size: 0.85rem; color: #8888a0;">
        <a href="https://sentinel.copilotkit.dev">Sentinel</a> — open-source CI/CD security scanner.
        <a href="https://github.com/jpr5/sentinel">Source</a>
      </p>
    </body>
    </html>
    HTML
end

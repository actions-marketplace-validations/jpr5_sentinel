#!/usr/bin/env ruby

require "sinatra"
require "json"
require "time"
require_relative "audit"
require_relative "config"
require_relative "github_app_auth"
require_relative "queue"
require_relative "state"
require_relative "pr_writer"

AUDIT = Bot::Audit.new

set :port, ENV["PORT"] || 3000
set :bind, "0.0.0.0"
set :environment, :production

# Landing page
get "/" do
    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sentinel Bot</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Sentinel Bot">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
    </head>
    <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
      <h1>&#x1f6e1;&#xfe0f; Sentinel Bot</h1>
      <p>This bot scans popular open-source repos for CI/CD security vulnerabilities
         and opens fix PRs.</p>
      <p><a href="/dashboard">Dashboard</a> &middot;
         <a href="/queue">Approval Queue</a> &middot;
         <a href="/scan">Scan</a> &middot;
         <a href="https://sentinel.copilotkit.dev">Learn more</a> &middot;
         <a href="https://github.com/jpr5/sentinel">Source code</a></p>
    </body>
    </html>
    HTML
end

# PR lifecycle dashboard
get "/dashboard" do
    state = Bot::State.new
    prs = state.all_tracked_prs
    issues = state.all_tracked_issues

    # Determine excluded statuses: URL param takes precedence, then persisted preference
    excluded = if params["exclude"]
        params["exclude"].split(",").map(&:strip).reject(&:empty?)
    else
        state.dashboard_excluded_statuses
    end

    # Filter out excluded statuses
    if excluded.any?
        prs.reject! { |e| excluded.include?(e[:pr]["status"] || "open") }
        issues.reject! { |e| excluded.include?(e[:pr]["status"] || "open") }
    end

    status_priority = { "blocked" => 0, "open" => 1, "merged" => 2, "closed" => 3 }
    sort_fn = proc do |entries|
        entries.sort_by! do |entry|
            [
                status_priority[entry[:pr]["status"]] || 99,
                -(Time.parse(entry[:pr]["last_updated_at"]) rescue Time.at(0)).to_f
            ]
        end
    end
    sort_fn.call(prs)
    sort_fn.call(issues)

    pr_counts = { "merged" => 0, "open" => 0, "blocked" => 0, "closed" => 0 }
    prs.each { |e| pr_counts[e[:pr]["status"]] = (pr_counts[e[:pr]["status"]] || 0) + 1 }

    issue_counts = { "merged" => 0, "open" => 0, "blocked" => 0, "closed" => 0 }
    issues.each { |e| issue_counts[e[:pr]["status"]] = (issue_counts[e[:pr]["status"]] || 0) + 1 }

    build_table = proc do |entries, link_type|
        if entries.empty?
            "<div class=\"empty\"><p>No tracked #{link_type == :issue ? "issues" : "PRs"}.</p></div>"
        else
            rows = entries.map do |entry|
                repo = entry[:repo]
                pr = entry[:pr]
                number = pr["number"]
                status = pr["status"] || "open"
                created = format_time_pacific(pr["created_at"])
                updated = format_time_pacific(pr["last_updated_at"])
                note = pr["note"]

                link_path = link_type == :issue ? "issues" : "pull"
                num_header = link_type == :issue ? "#" : "PR"

                <<~ROW
                <tr>
                  <td><a href="https://github.com/#{escape_html(repo)}">#{escape_html(repo)}</a></td>
                  <td><a href="https://github.com/#{escape_html(repo)}/#{link_path}/#{number}">##{number}</a></td>
                  <td><span class="status status-#{escape_html(status)}">#{escape_html(status)}</span></td>
                  <td>#{escape_html(created)}</td>
                  <td>#{escape_html(updated)}</td>
                  <td class="note">#{note ? escape_html(note) : ""}</td>
                </tr>
                ROW
            end.join

            num_header = link_type == :issue ? "#" : "PR"
            <<~TABLE
            <table>
              <thead>
                <tr>
                  <th>Repo</th>
                  <th>#{num_header}</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Updated</th>
                  <th>Note</th>
                </tr>
              </thead>
              <tbody>
                #{rows}
              </tbody>
            </table>
            TABLE
        end
    end

    pr_table = build_table.call(prs, :pr)
    issue_table = build_table.call(issues, :issue)

    pr_total = prs.length
    issue_total = issues.length

    # Combined summary line
    summary_parts = []
    pr_summary = ["merged", "open", "blocked", "closed"]
        .select { |s| pr_counts[s] > 0 }
        .map { |s| "#{pr_counts[s]} #{s}" }
    summary_parts << "PRs: #{pr_summary.any? ? pr_summary.join(", ") : "0"}"

    issue_summary = ["open", "closed"]
        .select { |s| issue_counts[s] > 0 }
        .map { |s| "#{issue_counts[s]} #{s}" }
    summary_parts << "Issues: #{issue_summary.any? ? issue_summary.join(", ") : "0"}"

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Dashboard — Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Dashboard &mdash; Sentinel Bot">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 1100px; margin: 50px auto; padding: 0 20px; }
        h1 { color: #ff4444; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { text-align: left; padding: 8px 12px; border-bottom: 2px solid #2a2a3a; color: #8888a0; font-weight: 500; }
        td { padding: 8px 12px; border-bottom: 1px solid #1a1a2a; }
        a { color: #ff4444; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .status { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .status-merged { background: rgba(34,197,94,0.15); color: #22c55e; }
        .status-open { background: rgba(234,179,8,0.15); color: #eab308; }
        .status-blocked { background: rgba(239,68,68,0.15); color: #ef4444; }
        .status-closed { background: rgba(107,114,128,0.15); color: #6b7280; }
        .note { color: #8888a0; font-size: 0.85rem; }
        .summary { margin-top: 1.5rem; color: #8888a0; font-size: 0.9rem; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
        .empty { text-align: center; padding: 3rem; color: #8888a0; }
        .filter-indicator { color: #eab308; font-size: 0.85rem; margin-bottom: 1rem; }
        .tabs { display: flex; gap: 0; margin-bottom: 1.5rem; border-bottom: 2px solid #2a2a3a; }
        .tab { background: none; border: none; color: #8888a0; padding: 8px 16px; cursor: pointer; font-size: 0.95rem; border-bottom: 2px solid transparent; margin-bottom: -2px; }
        .tab.active { color: #ff4444; border-bottom-color: #ff4444; }
        .tab .badge { background: rgba(255,68,68,0.15); color: #ff4444; padding: 1px 6px; border-radius: 10px; font-size: 0.8rem; margin-left: 6px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
      </style>
      <script>
        function showTab(name) {
          document.querySelectorAll('.tab-content').forEach(function(el) { el.classList.remove('active'); });
          document.querySelectorAll('.tab').forEach(function(el) { el.classList.remove('active'); });
          document.getElementById(name).classList.add('active');
          document.querySelector('[onclick*="' + name + '"]').classList.add('active');
        }
      </script>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / dashboard
      </div>
      <h1>PR Tracker</h1>
      #{excluded.any? ? "<div class=\"filter-indicator\">Excluding: #{escape_html(excluded.join(", "))}</div>" : ""}
      <div class="tabs">
        <button class="tab active" onclick="showTab('prs')">Pull Requests <span class="badge">#{pr_total}</span></button>
        <button class="tab" onclick="showTab('issues')">Issues <span class="badge">#{issue_total}</span></button>
      </div>
      <div id="prs" class="tab-content active">
        #{pr_table}
      </div>
      <div id="issues" class="tab-content">
        #{issue_table}
      </div>
      <div class="summary">#{summary_parts.join(" | ")}</div>
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
    <head>
      <title>Opt Out &mdash; Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Sentinel Bot">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
    </head>
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

    if ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
        require_relative "backup"
        Bot::Backup.new(token: ENV["GITHUB_TOKEN"]).save rescue nil
    end

    AUDIT.opt_out(repo)
    consume_token(token)

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <title>Opted Out &mdash; Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Sentinel Bot">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
    </head>
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
    <head>
      <title>Adopt Sentinel &mdash; Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Sentinel Bot">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
    </head>
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
        AUDIT.adopt(repo)
        AUDIT.pr_created(repo, pr["html_url"])
        content_type :html
        <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>PR Created &mdash; Sentinel</title>
          <link rel="icon" type="image/svg+xml" href="/favicon.svg">
          <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
          <meta property="og:title" content="Sentinel Bot">
          <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
        </head>
        <body style="font-family: system-ui; max-width: 600px; margin: 50px auto; padding: 0 20px;">
          <h1>&#x2705; PR created</h1>
          <p>A pull request has been opened to add Sentinel to <strong>#{escape_html(repo)}</strong>.</p>
          <p><a href="#{escape_html(pr["html_url"])}">Review the PR &rarr;</a></p>
        </body>
        </html>
        HTML
    else
        AUDIT.adopt(repo)
        AUDIT.pr_failed(repo, "create_pr_returned_nil")
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
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="Security Rules &mdash; Sentinel">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
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

# Static assets
get "/favicon.ico" do
    content_type "image/png"
    send_file File.join(File.dirname(__FILE__), "assets", "favicon.png")
end

get "/favicon.svg" do
    content_type "image/svg+xml"
    send_file File.join(File.dirname(__FILE__), "assets", "favicon.svg")
end

get "/og-image.png" do
    content_type "image/png"
    send_file File.join(File.dirname(__FILE__), "assets", "og-image.png")
end

# Approval queue UI

get "/queue" do
    queue = Bot::Queue.new

    pending_rows = queue.pending.map do |item|
        type_badge = item["type"] == "issue" ? '<span class="type-badge type-issue">Issue</span>' : '<span class="type-badge type-pr">PR</span>'
        finding_count = (item["findings"] || []).length
        queued = format_time_pacific(item["queued_at"])
        id_short = item["id"][0, 8]

        <<~ROW
        <tr>
          <td>#{type_badge}</td>
          <td><a href="https://github.com/#{escape_html(item["repo"])}">#{escape_html(item["repo"])}</a></td>
          <td><a href="/queue/#{escape_html(item["id"])}">#{escape_html(item["title"])}</a></td>
          <td>#{finding_count}</td>
          <td>#{escape_html(queued)}</td>
          <td class="actions">
            <a href="/queue/#{escape_html(item["id"])}" class="btn btn-view">View</a>
            <form method="POST" action="/queue/#{escape_html(item["id"])}/approve" style="display:inline">
              <button type="submit" class="btn btn-approve">Approve</button>
            </form>
            <form method="POST" action="/queue/#{escape_html(item["id"])}/reject" style="display:inline">
              <button type="submit" class="btn btn-reject">Reject</button>
            </form>
          </td>
        </tr>
        ROW
    end.join

    approved_rows = queue.approved.map do |item|
        type_badge = item["type"] == "issue" ? '<span class="type-badge type-issue">Issue</span>' : '<span class="type-badge type-pr">PR</span>'
        approved_at = format_time_pacific(item["approved_at"])
        <<~ROW
        <tr>
          <td>#{type_badge}</td>
          <td>#{escape_html(item["repo"])}</td>
          <td>#{escape_html(item["title"])}</td>
          <td>#{escape_html(approved_at)}</td>
        </tr>
        ROW
    end.join

    rejected_rows = queue.rejected.map do |item|
        type_badge = item["type"] == "issue" ? '<span class="type-badge type-issue">Issue</span>' : '<span class="type-badge type-pr">PR</span>'
        rejected_at = format_time_pacific(item["rejected_at"])
        reason = item["reason"] ? escape_html(item["reason"]) : "<em>none</em>"
        <<~ROW
        <tr>
          <td>#{type_badge}</td>
          <td>#{escape_html(item["repo"])}</td>
          <td>#{escape_html(item["title"])}</td>
          <td>#{reason}</td>
          <td>#{escape_html(rejected_at)}</td>
        </tr>
        ROW
    end.join

    flash_msg = params["flash"] ? "<div class=\"flash\">#{escape_html(params["flash"])}</div>" : ""

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Approval Queue — Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 1100px; margin: 50px auto; padding: 0 20px; }
        h1 { color: #ff4444; }
        h2 { color: #e8e8f0; margin-top: 2rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { text-align: left; padding: 8px 12px; border-bottom: 2px solid #2a2a3a; color: #8888a0; font-weight: 500; }
        td { padding: 8px 12px; border-bottom: 1px solid #1a1a2a; }
        a { color: #ff4444; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
        .type-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .type-pr { background: rgba(34,197,94,0.15); color: #22c55e; }
        .type-issue { background: rgba(234,179,8,0.15); color: #eab308; }
        .btn { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; border: none; cursor: pointer; text-decoration: none; }
        .btn-view { background: rgba(136,136,160,0.15); color: #8888a0; }
        .btn-approve { background: rgba(34,197,94,0.15); color: #22c55e; }
        .btn-reject { background: rgba(239,68,68,0.15); color: #ef4444; }
        .btn:hover { opacity: 0.8; }
        .actions { white-space: nowrap; }
        .empty { text-align: center; padding: 2rem; color: #8888a0; }
        .flash { background: rgba(34,197,94,0.15); color: #22c55e; padding: 10px 16px; border-radius: 6px; margin-bottom: 1.5rem; }
        .summary { margin-top: 1.5rem; color: #8888a0; font-size: 0.9rem; }
        details { margin-top: 1.5rem; }
        summary { cursor: pointer; color: #8888a0; font-size: 0.95rem; }
        summary:hover { color: #e8e8f0; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / <a href="/dashboard">dashboard</a> / queue
        &middot; <a href="/scan">scan</a>
      </div>
      <h1>Approval Queue</h1>
      #{flash_msg}
      <h2>Pending (#{queue.pending.length})</h2>
      #{if queue.pending.empty?
          '<div class="empty">No items pending approval.</div>'
        else
          <<~TABLE
          <table>
            <thead>
              <tr><th>Type</th><th>Repo</th><th>Title</th><th>Findings</th><th>Queued</th><th>Actions</th></tr>
            </thead>
            <tbody>#{pending_rows}</tbody>
          </table>
          TABLE
        end}
      <details>
        <summary>Approved (#{queue.approved.length})</summary>
        #{if queue.approved.empty?
            '<div class="empty">No approved items.</div>'
          else
            <<~TABLE
            <table>
              <thead>
                <tr><th>Type</th><th>Repo</th><th>Title</th><th>Approved</th></tr>
              </thead>
              <tbody>#{approved_rows}</tbody>
            </table>
            TABLE
          end}
      </details>
      <details>
        <summary>Rejected (#{queue.rejected.length})</summary>
        #{if queue.rejected.empty?
            '<div class="empty">No rejected items.</div>'
          else
            <<~TABLE
            <table>
              <thead>
                <tr><th>Type</th><th>Repo</th><th>Title</th><th>Reason</th><th>Rejected</th></tr>
              </thead>
              <tbody>#{rejected_rows}</tbody>
            </table>
            TABLE
          end}
      </details>
      <div class="summary">#{queue.pending.length} pending | #{queue.approved.length} approved | #{queue.rejected.length} rejected</div>
    </body>
    </html>
    HTML
end

get "/queue/:id" do
    queue = Bot::Queue.new

    # Support prefix match like the CLI
    item = queue.pending.find { |i| i["id"] == params["id"] || i["id"].start_with?(params["id"]) }
    halt 404, "Item not found in queue" unless item

    type_badge = item["type"] == "issue" ? '<span class="type-badge type-issue">Issue</span>' : '<span class="type-badge type-pr">PR</span>'
    finding_count = (item["findings"] || []).length
    queued = format_time_pacific(item["queued_at"])
    body_html = markdown_to_html(item["body"] || "")

    files_html = ""
    if item["files"] && !item["files"].empty?
        files_html = '<h2>File Changes</h2>'
        item["files"].each do |file_path, content|
            files_html += <<~FILE
            <div class="file-change">
              <div class="file-header">#{escape_html(file_path)}</div>
              <pre><code>#{escape_html(content)}</code></pre>
            </div>
            FILE
        end
    end

    findings_html = ""
    if item["findings"] && !item["findings"].empty?
        findings_html = '<h2>Findings</h2>'
        item["findings"].each do |f|
            severity = f["severity"] || "unknown"
            findings_html += <<~FINDING
            <div class="finding">
              <div class="finding-header">
                <span class="finding-rule">#{escape_html(f["rule"] || "")}</span>
                <span class="finding-severity severity-#{escape_html(severity.to_s)}">#{escape_html(severity.to_s)}</span>
              </div>
              <div class="finding-location">#{escape_html(f["file"] || "")}:#{f["line"]}</div>
              <div class="finding-message">#{escape_html(f["message"] || "")}</div>
              #{f["fix"] ? "<div class=\"finding-fix\"><strong>Fix:</strong> #{escape_html(f["fix"])}</div>" : ""}
            </div>
            FINDING
        end
    end

    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>#{escape_html(item["title"])} — Queue — Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 900px; margin: 50px auto; padding: 0 20px; line-height: 1.7; }
        h1 { color: #ff4444; margin-bottom: 0.5rem; }
        h2 { color: #e8e8f0; margin-top: 2rem; border-bottom: 1px solid #2a2a3a; padding-bottom: 0.5rem; }
        a { color: #ff4444; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { font-family: "JetBrains Mono", monospace; background: #16161f; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
        pre { background: #16161f; border: 1px solid #2a2a3a; border-radius: 8px; padding: 1rem; overflow-x: auto; }
        pre code { background: none; padding: 0; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
        .type-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .type-pr { background: rgba(34,197,94,0.15); color: #22c55e; }
        .type-issue { background: rgba(234,179,8,0.15); color: #eab308; }
        .meta { color: #8888a0; font-size: 0.9rem; margin-bottom: 1.5rem; }
        .action-bar { margin: 1.5rem 0; display: flex; gap: 10px; align-items: center; }
        .btn { display: inline-block; padding: 8px 20px; border-radius: 6px; font-size: 0.9rem; font-weight: 500; border: none; cursor: pointer; text-decoration: none; }
        .btn-approve { background: rgba(34,197,94,0.25); color: #22c55e; }
        .btn-reject { background: rgba(239,68,68,0.25); color: #ef4444; }
        .btn-back { background: rgba(136,136,160,0.15); color: #8888a0; }
        .btn:hover { opacity: 0.8; }
        .reject-reason { background: #16161f; border: 1px solid #2a2a3a; color: #e8e8f0; padding: 6px 10px; border-radius: 4px; font-size: 0.85rem; width: 200px; }
        .body-content { background: #12121a; border: 1px solid #1a1a2a; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }
        .body-content p { margin: 0.5rem 0; }
        .body-content h1, .body-content h2 { color: #e8e8f0; }
        .body-content ul { padding-left: 1.5rem; }
        .body-content strong { color: #ff4444; }
        .file-change { margin: 1rem 0; }
        .file-header { background: #1a1a2a; padding: 6px 12px; border-radius: 6px 6px 0 0; border: 1px solid #2a2a3a; border-bottom: none; font-family: "JetBrains Mono", monospace; font-size: 0.85rem; color: #8888a0; }
        .file-change pre { margin-top: 0; border-radius: 0 0 8px 8px; }
        .finding { background: #12121a; border: 1px solid #1a1a2a; border-radius: 6px; padding: 1rem; margin: 0.75rem 0; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
        .finding-rule { font-weight: 600; color: #e8e8f0; }
        .finding-severity { padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .severity-critical { background: rgba(239,68,68,0.15); color: #ef4444; }
        .severity-high { background: rgba(249,115,22,0.15); color: #f97316; }
        .severity-medium { background: rgba(234,179,8,0.15); color: #eab308; }
        .severity-low { background: rgba(107,114,128,0.15); color: #6b7280; }
        .severity-unknown { background: rgba(107,114,128,0.15); color: #6b7280; }
        .finding-location { font-family: "JetBrains Mono", monospace; font-size: 0.85rem; color: #8888a0; }
        .finding-message { margin-top: 0.5rem; }
        .finding-fix { margin-top: 0.5rem; color: #22c55e; font-size: 0.9rem; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / <a href="/dashboard">dashboard</a> / <a href="/queue">queue</a> / #{escape_html(item["id"][0, 8])}
      </div>
      <h1>#{escape_html(item["title"])}</h1>
      <div class="meta">
        #{type_badge}
        &middot; <a href="https://github.com/#{escape_html(item["repo"])}">#{escape_html(item["repo"])}</a>
        &middot; #{finding_count} finding#{finding_count == 1 ? "" : "s"}
        &middot; Queued #{escape_html(queued)}
      </div>
      <div class="action-bar">
        <form method="POST" action="/queue/#{escape_html(item["id"])}/approve" style="display:inline">
          <button type="submit" class="btn btn-approve">Approve</button>
        </form>
        <form method="POST" action="/queue/#{escape_html(item["id"])}/reject" style="display:inline;display:flex;gap:6px;align-items:center;">
          <input type="text" name="reason" placeholder="Rejection reason (optional)" class="reject-reason">
          <button type="submit" class="btn btn-reject">Reject</button>
        </form>
        <a href="/queue" class="btn btn-back">Back to queue</a>
      </div>
      <h2>PR/Issue Body</h2>
      <div class="body-content">
        #{body_html}
      </div>
      #{files_html}
      #{findings_html}
      <div class="action-bar">
        <form method="POST" action="/queue/#{escape_html(item["id"])}/approve" style="display:inline">
          <button type="submit" class="btn btn-approve">Approve</button>
        </form>
        <form method="POST" action="/queue/#{escape_html(item["id"])}/reject" style="display:inline;display:flex;gap:6px;align-items:center;">
          <input type="text" name="reason" placeholder="Rejection reason (optional)" class="reject-reason">
          <button type="submit" class="btn btn-reject">Reject</button>
        </form>
        <a href="/queue" class="btn btn-back">Back to queue</a>
      </div>
    </body>
    </html>
    HTML
end

post "/queue/:id/approve" do
    queue = Bot::Queue.new

    # Support prefix match like the CLI
    match = queue.pending.find { |i| i["id"] == params["id"] || i["id"].start_with?(params["id"]) }
    halt 404, "Item not found in queue" unless match

    token = ENV["GITHUB_TOKEN"]
    if ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"]
        auth = Bot::GitHubAppAuth.new
        token = auth.token_for(match["repo"]) || token
    end
    halt 500, "Bot not configured (missing credentials)" unless token

    item = queue.approve(match["id"])
    queue.save

    if ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
        require_relative "backup"
        Bot::Backup.new(token: ENV["GITHUB_TOKEN"]).save rescue nil
    end

    AUDIT.log("QUEUE_APPROVE", repo: item["repo"], details: "id=#{match["id"][0, 8]} type=#{item["type"] || "pr"} via=web")

    writer = Bot::PrWriter.new(token: token)
    state = Bot::State.new

    if item["type"] == "issue"
        result = writer.create_issue(
            repo: item["repo"],
            title: item["title"],
            body: item["body"],
            labels: ["security"]
        )

        if result
            AUDIT.issue_created(item["repo"], result["html_url"])
            (item["findings"] || []).each do |f|
                state.record_pr(item["repo"], result["html_url"], f["rule"], result["number"], type: "issue")
            end
            state.save

            content_type :html
            <<~HTML
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>Issue Created — Sentinel</title>
              <link rel="icon" type="image/svg+xml" href="/favicon.svg">
              <style>
                body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 600px; margin: 50px auto; padding: 0 20px; }
                h1 { color: #22c55e; }
                a { color: #ff4444; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
                .nav a { color: #8888a0; }
              </style>
            </head>
            <body>
              <div class="nav">
                <a href="https://sentinel.copilotkit.dev">sentinel</a> / <a href="/queue">queue</a> / approved
              </div>
              <h1>Issue created</h1>
              <p>An issue has been opened on <strong>#{escape_html(item["repo"])}</strong>.</p>
              <p><a href="#{escape_html(result["html_url"])}">View issue on GitHub &rarr;</a></p>
              <p><a href="/queue">Back to queue</a></p>
            </body>
            </html>
            HTML
        else
            AUDIT.issue_failed(item["repo"], "create_issue_returned_nil")
            halt 500, "Failed to create issue for #{escape_html(item["repo"])}"
        end
    else
        result = writer.create_pr(
            repo: item["repo"],
            branch: "sentinel/security-fixes",
            title: item["title"],
            body: item["body"],
            files: item["files"] || {},
            signoff: item["signoff"]
        )

        if result
            AUDIT.pr_created(item["repo"], result["html_url"])
            (item["findings"] || []).each do |f|
                state.record_pr(item["repo"], result["html_url"], f["rule"], result["number"])
            end
            state.save

            content_type :html
            <<~HTML
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>PR Created — Sentinel</title>
              <link rel="icon" type="image/svg+xml" href="/favicon.svg">
              <style>
                body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 600px; margin: 50px auto; padding: 0 20px; }
                h1 { color: #22c55e; }
                a { color: #ff4444; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
                .nav a { color: #8888a0; }
              </style>
            </head>
            <body>
              <div class="nav">
                <a href="https://sentinel.copilotkit.dev">sentinel</a> / <a href="/queue">queue</a> / approved
              </div>
              <h1>PR created</h1>
              <p>A pull request has been opened on <strong>#{escape_html(item["repo"])}</strong>.</p>
              <p><a href="#{escape_html(result["html_url"])}">View PR on GitHub &rarr;</a></p>
              <p><a href="/queue">Back to queue</a></p>
            </body>
            </html>
            HTML
        else
            AUDIT.pr_failed(item["repo"], "create_pr_returned_nil")
            halt 500, "Failed to create PR for #{escape_html(item["repo"])}"
        end
    end
end

post "/queue/:id/reject" do
    queue = Bot::Queue.new

    match = queue.pending.find { |i| i["id"] == params["id"] || i["id"].start_with?(params["id"]) }
    halt 404, "Item not found in queue" unless match

    reason = params["reason"]&.strip
    reason = nil if reason&.empty?

    item = queue.reject(match["id"], reason: reason)
    queue.save

    if ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
        require_relative "backup"
        Bot::Backup.new(token: ENV["GITHUB_TOKEN"]).save rescue nil
    end

    AUDIT.log("QUEUE_REJECT", repo: item["repo"], details: "id=#{match["id"][0, 8]} reason=#{reason || 'none'} via=web")

    redirect "/queue?flash=Rejected: #{item["repo"]} — #{item["title"]}"
end

# Scan trigger page
get "/scan" do
    content_type :html
    <<~HTML
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Scan — Sentinel</title>
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0f; color: #e8e8f0; max-width: 600px; margin: 50px auto; padding: 0 20px; }
        h1 { color: #ff4444; }
        a { color: #ff4444; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .nav { font-size: 0.85rem; color: #8888a0; margin-bottom: 2rem; }
        .nav a { color: #8888a0; }
        label { display: block; margin-top: 1rem; color: #8888a0; font-size: 0.9rem; }
        input[type="number"] {
          display: block; margin-top: 0.3rem; padding: 8px 12px; border-radius: 6px;
          border: 1px solid #2a2a3a; background: #16161f; color: #e8e8f0; font-size: 0.95rem;
          width: 100%; box-sizing: border-box;
        }
        button[type="submit"] {
          margin-top: 1.5rem; padding: 10px 24px; border-radius: 6px; border: none;
          background: rgba(255,68,68,0.2); color: #ff4444; font-size: 1rem;
          font-weight: 500; cursor: pointer;
        }
        button[type="submit"]:hover { background: rgba(255,68,68,0.3); }
        .note { margin-top: 1rem; color: #8888a0; font-size: 0.85rem; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="https://sentinel.copilotkit.dev">sentinel</a> / scan
      </div>
      <h1>Start Scan</h1>
      <p>Run a security scan against public repos. Findings go to the
         <a href="/queue">approval queue</a> for review before any PRs are opened.</p>
      <form method="POST" action="/scan">
        <input type="hidden" name="pattern" value="rotate">
        <label for="limit">Repos to scan (max 50)</label>
        <input type="number" name="limit" id="limit" value="10" min="1" max="50">
        <button type="submit">Start Scan</button>
      </form>
      <p class="note">Rotates through search queries automatically. May take 30-120 seconds.</p>
    </body>
    </html>
    HTML
end

# Execute scan
post "/scan" do
    token = ENV["GITHUB_TOKEN"]
    halt 500, "GITHUB_TOKEN not configured" unless token

    pattern = params["pattern"] || "rotate"
    limit = [[(params["limit"] || "5").to_i, 1].max, 50].min

    require_relative "scanner_bot"
    bot = Bot::ScannerBot.new(
        token: token,
        pattern: pattern,
        dry_run: false,
        limit: limit,
        queue_mode: true
    )
    bot.run

    redirect "/queue"
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

    if ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
        require_relative "backup"
        Bot::Backup.new(token: ENV["GITHUB_TOKEN"]).save rescue nil
    end
end

def format_time_pacific(iso_string)
    return "-" unless iso_string
    utc = Time.parse(iso_string).utc
    # Determine if PDT or PST applies using US DST rules
    # DST: second Sunday in March to first Sunday in November
    year = utc.year
    mar_second_sun = Time.utc(year, 3, 8) + ((7 - Time.utc(year, 3, 8).wday) % 7) * 86400
    nov_first_sun = Time.utc(year, 11, 1) + ((7 - Time.utc(year, 11, 1).wday) % 7) * 86400
    # DST transitions at 2:00 AM local = 10:00 AM UTC (PDT start) / 9:00 AM UTC (PST start)
    pdt_start = mar_second_sun + 10 * 3600
    pst_start = nov_first_sun + 9 * 3600
    offset = (utc >= pdt_start && utc < pst_start) ? "-07:00" : "-08:00"
    t = utc.getlocal(offset)
    hour = t.hour % 12
    hour = 12 if hour == 0
    ampm = t.hour < 12 ? "a" : "p"
    t.strftime("%b %-d ") + "#{hour}:#{"%02d" % t.min}#{ampm}"
end

def escape_html(text)
    text.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;").gsub("'", "&#39;")
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
    # Links (validate URL scheme to prevent javascript: URLs)
    text = text.gsub(/\[([^\]]+)\]\(([^)]+)\)/) do
        link_text = $1
        url = $2
        href = url.match?(/\Ahttps?:\/\//) ? url : "#"
        "<a href=\"#{href}\">#{link_text}</a>"
    end
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
      <link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <meta property="og:image" content="https://sentinel-bot.copilotkit.dev/og-image.png">
      <meta property="og:title" content="#{escape_html(rule)} &mdash; Sentinel">
      <meta property="og:description" content="CI/CD security scanner for GitHub Actions workflows">
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

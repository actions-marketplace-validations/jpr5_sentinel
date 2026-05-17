#!/usr/bin/env ruby

require "sinatra"
require "json"
require_relative "config"
require_relative "github_app_auth"
require_relative "state"
require_relative "pr_writer"

set :port, ENV["PORT"] || 3000
set :bind, "0.0.0.0"

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

# Opt out -- one click, done
get "/opt-out" do
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

# Adopt -- creates a PR adding the Sentinel GitHub Action to the repo
get "/adopt" do
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

# Sentinel

**Deterministic security scanner for GitHub Actions workflows**

<!-- badges -->
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)
![License](https://img.shields.io/badge/license-MIT-blue)

Scan GitHub Actions workflows for 28 security vulnerabilities. Optional AI-powered remediation via Claude. Pure Ruby stdlib.

Documentation: https://sentinel.copilotkit.dev

## Install

```bash
# Zero-config for public repos — no GITHUB_TOKEN needed
gem install sentinel-ci
sentinel scan owner/repo

# One-shot (like npx)
gem exec sentinel-ci scan owner/repo

# For private repos or org scanning, set a token
export GITHUB_TOKEN=$(gh auth token)
sentinel scan --org my-org
```

Requires Ruby 3.2+ and `git`. Public repos are scanned via shallow clone -- no API token required.
For private repos or `--org` scanning, set `GITHUB_TOKEN`.

## Usage

```bash
# Scan a single repo
sentinel scan owner/repo

# Scan a local checkout
sentinel scan --local /path/to/repo

# Scan an entire GitHub org
sentinel scan --org my-org

# JSON output, filter to high+ severity
sentinel scan --format json --severity high owner/repo

# SARIF output for GitHub Security tab
sentinel scan --format sarif owner/repo > results.sarif
```

## GitHub Action

Use as a GitHub Action to automatically scan workflows on every PR:

```yaml
- uses: jpr5/sentinel@v1
  with:
    severity: high
```

Full workflow example:

```yaml
name: Workflow Security Scan
on:
  pull_request:
    paths: ['.github/workflows/**']
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jpr5/sentinel@v1
        id: scan
        with:
          severity: high
          fail-on-findings: true
```

**Inputs:**

| Name | Default | Description |
|------|---------|-------------|
| `severity` | `high` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `fail-on-findings` | `true` | Fail the check if findings above threshold exist |

**Outputs:**

| Name | Description |
|------|-------------|
| `findings-count` | Total findings at or above severity |
| `critical-count` | Critical findings count |
| `high-count` | High findings count |

Findings appear as inline annotations on the PR diff -- critical/high as errors,
medium as warnings, low as notices.

## Pre-commit Hook

Scan workflow files automatically before every commit:

```bash
# Auto-install
sentinel hook install

# Manual removal
sentinel hook uninstall
```

Works with hook managers too:

```bash
# husky
echo 'sentinel hook run' >> .husky/pre-commit

# lefthook (lefthook.yml)
pre-commit:
  commands:
    sentinel:
      glob: ".github/workflows/*.{yml,yaml}"
      run: sentinel hook run
```

The hook only runs when `.github/workflows/*.yml` files are staged, so it won't slow down unrelated commits.

## What It Checks

| # | Rule | Severity | What |
|---|------|----------|------|
| 1 | `unpinned-actions` | critical/medium | Tag-pinned actions (critical for third-party, medium for `actions/*`) |
| 2 | `shell-injection-expr` | critical | Attacker-controllable `${{ }}` in `run:` blocks |
| 3 | `shell-injection-jq` | critical | `${VAR}` in double-quoted jq/curl strings |
| 4 | `hardcoded-secrets` | critical | AWS keys, GitHub PATs, private keys, passwords in plain text |
| 5 | `self-hosted-runner-fork` | critical | Self-hosted runner on fork PR triggers |
| 6 | `github-script-injection` | critical | Attacker-controllable `${{ }}` in github-script |
| 7 | `dangerous-triggers` | critical | `pull_request_target` + fork code checkout |
| 8 | `missing-persist-credentials` | high | `actions/checkout` without `persist-credentials: false` |
| 9 | `credential-window` | high | Git credentials configured far from push step |
| 10 | `static-aws-credentials` | high | Static AWS keys instead of OIDC federation |
| 11 | `unscoped-app-token` | high | `create-github-app-token` without `permission-*` scoping |
| 12 | `docker-build-arg-secrets` | high | Secrets in Docker build-args (visible in image layers) |
| 13 | `build-publish-same-job` | high | Build + publish in same job with publish secrets |
| 14 | `curl-pipe-shell` | high | `curl \| sh` without integrity verification |
| 15 | `workflow-dispatch-injection` | high | `${{ inputs.* }}` in run blocks |
| 16 | `missing-permissions` | medium | No top-level permissions block |
| 17 | `git-config-global` | medium | `git config --global` with credentials |
| 18 | `missing-timeouts` | medium | Jobs without `timeout-minutes` |
| 19 | `missing-env-protection` | medium | Publish/deploy jobs without environment protection |
| 20 | `allow-forks-artifact` | medium | Fork-produced artifact download in privileged context |
| 21 | `missing-frozen-lockfile` | medium | Package install without `--frozen-lockfile` / `npm ci` |
| 22 | `cache-poisoning` | medium | Cache keys with fork-controllable refs |
| 23 | `excessive-permissions` | medium | Write permissions on jobs that only read |
| 24 | `unpinned-artifact` | medium | download-artifact without specific name |
| 25 | `unpinned-docker-image` | low | Docker images using `:latest` tag |
| 26 | `overly-broad-triggers` | low | Push/PR triggers without branch/path filters |
| 27 | `missing-dependabot` | low | No Dependabot config for github-actions ecosystem |
| 28 | `missing-zizmor` | low | No zizmor static analysis workflow |

## Auto-Fix

Sentinel can automatically generate fixes for three rule categories:

```bash
sentinel scan --fix owner/repo    # future CLI flag
```

Or use the Ruby API directly:

```ruby
require_relative "lib/auto_fix"
require_relative "lib/sha_resolver"

resolver = ShaResolver.new
patched = AutoFix.apply(finding, raw_yaml, sha_resolver: resolver)
```

**Fixable rules:**

| Rule | Fix Strategy |
|------|-------------|
| `unpinned-actions` | Resolves tag to SHA via GitHub API |
| `shell-injection-expr` | Moves expression to step-level `env:` block |
| `missing-persist-credentials` | Adds `persist-credentials: false` to checkout |

## PR Bot

Proactively scan popular public repos and open fix PRs for critical findings.

```bash
ruby bot/scanner_bot.rb --pattern shell-injection --dry-run
```

**Features:**

- GitHub Code Search to find vulnerable repos
- Auto-generates fix PRs for mechanically-fixable rules
- Rate limited (50 PRs/day), stars threshold (>100)
- Opt-out support, clear bot identity
- Runs as daily cron via GitHub Actions

## MCP Server

Use Sentinel as a tool in AI coding agents (Claude Code, Copilot, Cursor):

```bash
# Start the MCP server
sentinel mcp

# Configure in Claude Code (~/.claude.json)
{
  "mcpServers": {
    "sentinel": {
      "command": "sentinel",
      "args": ["mcp"]
    }
  }
}
```

Three tools available: `sentinel_scan`, `sentinel_deps`, `sentinel_fix`.

## Supply Chain Analysis

Map third-party action dependencies with risk scoring:

```bash
sentinel deps --local .
sentinel deps owner/repo
sentinel deps --org my-org --format json
```

## Options

```
--format FORMAT    terminal (default), json, or sarif
--severity LEVEL   minimum severity: critical, high, medium, low (default: low)
--local PATH       scan local directory
--org ORG          scan all repos in a GitHub org (requires GITHUB_TOKEN)
--token TOKEN      GitHub API token — only needed for private repos and --org scanning
```

## Exit Codes

- `0` -- no critical or high findings
- `1` -- critical or high findings present
- `2` -- usage error

## Architecture

```
bin/sentinel                    # CLI entry point (subcommand dispatcher)
action/
  annotate.rb                   # GitHub Action annotation emitter
lib/
  scanner.rb                    # orchestrator
  rule_engine.rb                # loads + runs all rules
  workflow.rb                   # YAML parser + helpers
  finding.rb                    # finding data struct
  github_client.rb              # GitHub API client
  local_client.rb               # filesystem client
  clone_client.rb               # git-clone client for public repos
  auto_fix.rb                   # mechanical auto-fix engine
  ai_fix.rb                     # AI-powered fix via Claude
  sha_resolver.rb               # GitHub tag -> SHA resolver
  policy.rb                     # policy-as-code engine (.sentinel-ci.yml)
  supply_chain.rb               # action dependency graph + risk scoring
  version.rb                    # gem version constant
  cli/
    scan.rb                     # sentinel scan subcommand
    fix.rb                      # sentinel fix subcommand
    bot.rb                      # sentinel bot subcommand
    hook.rb                     # sentinel hook install/uninstall
    deps.rb                     # sentinel deps subcommand
  formatter/
    terminal.rb                 # colored terminal output
    json.rb                     # JSON output
    sarif.rb                    # SARIF output for GitHub Security tab
  rules/
    base.rb                     # abstract rule interface
    *.rb                        # one file per rule (27 rules)
mcp/
  server.rb                     # MCP server for AI coding agents
  claude-code-config.json       # example configuration for Claude Code
bot/
  scanner_bot.rb                # PR bot orchestrator
  search.rb                     # GitHub Code Search client
  state.rb                      # JSON-file state tracking
  pr_writer.rb                  # cross-fork PR creation
  config.rb                     # bot configuration
```

## Adding Rules

Create `lib/rules/my_rule.rb`:

```ruby
module Rules
    class MyRule < Base
        def name = "my-rule"
        def description = "What this detects"
        def severity = :high  # :critical, :high, :medium, :low

        def check(workflow)
            findings = []
            # workflow.uses_actions, workflow.run_blocks, workflow.raw_lines, etc.
            # Use finding() helper or construct Finding.new() directly
            findings
        end
    end
end
```

Rules are auto-discovered from `lib/rules/`.

## License

MIT

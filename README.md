# Sentinel

**Deterministic security scanner for GitHub Actions workflows**

<!-- badges -->
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)
![License](https://img.shields.io/badge/license-MIT-blue)

Scan GitHub Actions workflows for 21 security vulnerabilities. No AI, no gems -- pure Ruby stdlib.

Documentation: https://sentinel.copilotkit.dev

## Install

```bash
# One-shot (like npx — Ruby 3.2+)
gem exec sentinel-ci scan owner/repo

# Or install globally
gem install sentinel-ci
sentinel scan owner/repo

# Or clone and run directly
git clone https://github.com/CopilotKit/sentinel.git
cd sentinel
export GITHUB_TOKEN=$(gh auth token)
bin/sentinel scan owner/repo
```

Requires Ruby 3.2+. No dependencies beyond stdlib (`yaml`, `net/http`, `optparse`, `json`).

## Usage

```bash
# Scan a single repo
bin/gh-workflow-scanner owner/repo

# Scan a local checkout
bin/gh-workflow-scanner --local /path/to/repo

# Scan an entire GitHub org
bin/gh-workflow-scanner --org my-org

# JSON output, filter to high+ severity
bin/gh-workflow-scanner --format json --severity high owner/repo
```

## GitHub Action

Use as a GitHub Action to automatically scan workflows on every PR:

```yaml
- uses: jpr5/gh-workflow-scanner-action@v1
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
      - uses: jpr5/gh-workflow-scanner-action@v1
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

## What It Checks

| # | Rule | Severity | What |
|---|------|----------|------|
| 1 | `unpinned-actions` | critical/medium | Tag-pinned actions (critical for third-party, medium for `actions/*`) |
| 2 | `shell-injection-expr` | critical | Attacker-controllable `${{ }}` in `run:` blocks |
| 3 | `shell-injection-jq` | critical | `${VAR}` in double-quoted jq/curl strings |
| 4 | `dangerous-triggers` | critical | `pull_request_target` + fork code checkout |
| 5 | `missing-persist-credentials` | high | `actions/checkout` without `persist-credentials: false` |
| 6 | `credential-window` | high | Git credentials configured far from push step |
| 7 | `static-aws-credentials` | high | Static AWS keys instead of OIDC federation |
| 8 | `unscoped-app-token` | high | `create-github-app-token` without `permission-*` scoping |
| 9 | `docker-build-arg-secrets` | high | Secrets in Docker build-args (visible in image layers) |
| 10 | `build-publish-same-job` | high | Build + publish in same job with publish secrets |
| 11 | `curl-pipe-shell` | high | `curl \| sh` without integrity verification |
| 12 | `missing-permissions` | medium | No top-level permissions block |
| 13 | `git-config-global` | medium | `git config --global` with credentials |
| 14 | `missing-timeouts` | medium | Jobs without `timeout-minutes` |
| 15 | `missing-env-protection` | medium | Publish/deploy jobs without environment protection |
| 16 | `allow-forks-artifact` | medium | Fork-produced artifact download in privileged context |
| 17 | `missing-frozen-lockfile` | medium | Package install without `--frozen-lockfile` / `npm ci` |
| 18 | `unpinned-docker-image` | low | Docker images using `:latest` tag |
| 19 | `overly-broad-triggers` | low | Push/PR triggers without branch/path filters |
| 20 | `missing-dependabot` | low | No Dependabot config for github-actions ecosystem |
| 21 | `missing-zizmor` | low | No zizmor static analysis workflow |

## Auto-Fix

Sentinel can automatically generate fixes for three rule categories:

```bash
bin/gh-workflow-scanner --fix owner/repo    # future CLI flag
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

## Options

```
--format FORMAT    terminal (default) or json
--severity LEVEL   minimum severity: critical, high, medium, low (default: low)
--local PATH       scan local directory
--org ORG          scan all repos in a GitHub org
--token TOKEN      GitHub API token (default: GITHUB_TOKEN env var)
```

## Exit Codes

- `0` -- no critical or high findings
- `1` -- critical or high findings present
- `2` -- usage error

## Architecture

```
bin/gh-workflow-scanner         # CLI entry point (optparse)
action/
  annotate.rb                   # GitHub Action annotation emitter
lib/
  scanner.rb                    # orchestrator
  rule_engine.rb                # loads + runs all rules
  workflow.rb                   # YAML parser + helpers
  finding.rb                    # finding data struct
  github_client.rb              # GitHub API client
  local_client.rb               # filesystem client
  auto_fix.rb                   # auto-fix engine
  sha_resolver.rb               # GitHub tag -> SHA resolver
  formatter/
    terminal.rb                 # colored terminal output
    json.rb                     # JSON output
  rules/
    base.rb                     # abstract rule interface
    *.rb                        # one file per rule (19 rules)
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

# gh-workflow-scanner

A deterministic Ruby CLI that audits GitHub Actions workflows for security
vulnerabilities across 20 dimensions. No AI, no gems -- pure Ruby stdlib.

## Install

```bash
git clone https://github.com/jpr5/gh-workflow-scanner.git
cd gh-workflow-scanner
export GITHUB_TOKEN=$(gh auth token)  # or set manually
```

Requires Ruby 3.1+. No dependencies beyond stdlib (`yaml`, `net/http`, `optparse`, `json`).

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

## Exit Codes

- `0` — no critical or high findings
- `1` — critical or high findings present
- `2` — usage error

## Options

```
--format FORMAT    terminal (default) or json
--severity LEVEL   minimum severity: critical, high, medium, low (default: low)
--local PATH       scan local directory
--org ORG          scan all repos in a GitHub org
--token TOKEN      GitHub API token (default: GITHUB_TOKEN env var)
```

## Architecture

```
bin/gh-workflow-scanner    # CLI entry point (optparse)
lib/
  scanner.rb               # orchestrator
  rule_engine.rb           # loads + runs all rules
  workflow.rb              # YAML parser + helpers
  finding.rb               # finding data struct
  github_client.rb         # GitHub API client
  local_client.rb          # filesystem client
  formatter/
    terminal.rb            # colored terminal output
    json.rb                # JSON output
  rules/
    base.rb                # abstract rule interface
    *.rb                   # one file per rule
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

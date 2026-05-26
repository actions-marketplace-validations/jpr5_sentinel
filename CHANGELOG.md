# Changelog

## 1.3.3 (2026-05-26)

### Bug Fixes
- build-publish-same-job: recognize `--ignore-scripts` / `--no-scripts` as a per-command mitigation (collapsing shell line continuations, stripping inline comments via a POSIX-correct helper). Reject `--ignore-scripts=false` and similar bypasses.
- hardcoded-secrets: allowlist `actions/setup-java` env-name slots (`server-username`, `server-password`, `gpg-passphrase`, `gpg-private-key`, `keystore-password`) when the value matches an UPPER_SNAKE_CASE env var name.
- github-script-injection: cover `${{ inputs.* }}` and `${{ github.event.inputs.* }}` references inside `actions/github-script` `script:` blocks. Remove 30-line outer and 15-line inner lookback caps so long script bodies / long `with:` / `env:` blocks no longer cause missed findings. Evaluate INPUT and DANGEROUS expression paths independently so the event guard is no longer bypassed by mixed-pattern lines and a workflow_dispatch-only trigger no longer short-circuits input checks.
- workflow-dispatch-injection: make `in_run_block?` robust to long run blocks and uncommon step properties (STEP_KEYS-anchored backward scan, no length cap). Discriminate step-level `run:` from a `with: { run: ... }` action parameter via YAML indent, eliminating false positives on composite actions that take a command as input.

## 1.3.2 (2026-05-22)

### Bug Fixes
- hardcoded-secrets: stop flagging bare uppercase env-var-name references in `with:` blocks (e.g. `server-password: MAVEN_PASSWORD` in `actions/setup-java`). These are env-var-name references read by the action, not literal passwords.

## 1.3.1 (2026-05-22)

### Bug Fixes
- Fix warn-only mode: read `INPUT_FAIL-ON-FINDINGS` env var (GitHub Actions passes docker action inputs with hyphens preserved, not converted to underscores)

## 1.3.0 (2026-05-18)

### New Features
- PR lifecycle tracker (state model, GitHub sync, bootstrap, CLI + web dashboards)
- jq-arg-escape-sequences rule (rule 32, total now 32)
- Audit trail wiring (12 audit calls across all bot decision points)
- Gist-based state backup (--backup/--restore, auto-backup after runs)

### Testing & CI
- Bot integration tests (19 tests covering decision flow)
- CI workflow (Ruby 3.2+3.3 matrix, self-scan on all PRs)
- 646 total tests

### Infrastructure
- Stable file locking for concurrent bot/web access
- PST/PDT timezone handling (correct year-round)

## 1.2.0 (2026-05-18)

### Bot Hardening
- Safety gates for all bot operations
- `--live` flag required for production bot runs (dry-run by default)
- Duplicate PR detection to avoid spamming repos
- Pre-flight validation before creating PRs

### Auto-Fix Bug Fixes
- Fix indentation corruption when inserting env blocks
- Fix duplicate env entries when multiple expressions on same line
- Fix incomplete replacement leaving partial expressions in run blocks
- Fix phantom targeting where fixes applied to wrong step
- Fix quote context handling for single-quoted expressions

### New Features
- YAML validation gate: reject fixes that produce invalid YAML
- Repo convention detection (CLA requirements, conventional commits, PR templates)
- Audit log for all bot actions (who, when, what, which repo)
- Human-in-the-loop approval queue for bot PRs
- DCO signing support for repos that require it

### Production Bug Fixes
- 6 broken production PRs fixed in-place

### New Supply Chain Rules
- ide-config-injection: detect committed IDE configs with malicious extensions
- dangerous-lifecycle-scripts: flag npm/pip lifecycle hooks that run arbitrary code
- github-dependency-refs: detect dependencies loaded from GitHub refs instead of registries

## 1.1.0 (2026-05-18)

### Severity Re-ranking
- Severities re-evaluated based on actual exploitability
- Only actively exploitable rules (shell injection, dangerous triggers, hardcoded secrets) are critical
- Unpinned actions downgraded to medium (requires maintainer compromise first)
- First-party actions (actions/*) downgraded to low

### Bot Improvements
- Consolidated PRs: one PR per repo instead of one per rule
- Rule explainer pages at sentinel-bot.copilotkit.dev/rules/*
- `--limit N` flag to cap repos scanned per run
- Skip repos that already use Sentinel
- Fix PR body includes "How this was detected" methodology disclosure
- Adopt + opt-out links with UUID tokens

### Infrastructure
- Bot web handler live at sentinel-bot.copilotkit.dev (Sinatra on Railway)
- GitHub App created (sentinel-ci-scanner) for future bot identity
- GHCR-based deploy pipeline with env var trigger for Railway
- Rule explainer pages served from markdown with dark theme

### Bug Fixes
- file_exists? returning true for 404s
- Sentinel skip check matching bare word instead of uses: reference
- Railway deploy: env var change triggers fresh image pull (serviceInstanceRedeploy doesn't)
- Sinatra host authorization in production mode


## 1.0.1 (2026-05-17)

- Smart clone auth: try HTTPS, SSH, then gh token — no manual GITHUB_TOKEN needed for private repos

## 1.0.0 (2026-05-16)

### New Features
- MCP server for AI coding agents (sentinel mcp)
- Remote fix with PR creation (sentinel fix owner/repo)
- Policy engine wired into GitHub Action

### Security Fixes
- Git credential leakage prevention in action fix mode
- Prompt injection mitigation in AI fix (XML fences + UNTRUSTED warning)
- Annotation injection sanitization
- Tempfile race condition in policy loading

### Test Coverage
- 459 tests, 1358 assertions
- Added: ShaResolver, RuleEngine, bot state, formatter, CLI fix tests
- All 28 rules have test coverage

## 0.2.0 (2026-05-16)

### New Rules (7)
- hardcoded-secrets (critical)
- self-hosted-runner-fork (critical)
- github-script-injection (critical)
- workflow-dispatch-injection (high)
- cache-poisoning (medium)
- excessive-permissions (medium)
- unpinned-artifact (medium)

### New Features
- SARIF output format (--format sarif) for GitHub Security tab
- Policy-as-code engine (.sentinel-ci.yml)
- Supply chain graph (sentinel deps)
- Pre-commit hook (sentinel hook install)
- AI-powered fixes via Claude Opus (sentinel fix --ai)
- 6 mechanical auto-fixes (sentinel fix --local .)
- GitHub Action fix mode (fix: true)
- GitLab CI and Bitbucket Pipelines support (--platform)
- RubyGems trusted publishing (OIDC)
- Clone-based scanning for public repos (no GITHUB_TOKEN needed)
- Auto-detect gh auth token

### Language Expansion
- build-publish-same-job: 22 install + 18 publish patterns across 11 ecosystems
- missing-frozen-lockfile: JS, Python, Ruby, Go, Rust, PHP
- missing-env-protection: all publish/deploy patterns

### Improvements
- Severity split: first-party actions (medium) vs third-party (critical)
- curl-pipe-shell detects sudo variants
- shell-injection-expr covers github.actor, triggering_actor, workflow_run contexts

## 0.1.0 (2026-05-15)

Initial release.

- 21 security rules across 4 severity levels (critical, high, medium, low)
- GitHub API, local filesystem, and git-clone scanning modes
- Terminal and JSON output formatters
- GitHub Action with inline PR annotations
- Auto-fix engine for unpinned actions, shell injection, and persist-credentials
- PR bot for proactive scanning of popular public repos
- Subcommand CLI: `sentinel scan`, `sentinel fix`, `sentinel bot`
- Zero dependencies — pure Ruby stdlib
- Auto-detects `gh auth token` for seamless private repo access
- Shallow clone for public repos — no GITHUB_TOKEN needed

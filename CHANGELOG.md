# Changelog

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

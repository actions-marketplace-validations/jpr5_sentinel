# Changelog

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

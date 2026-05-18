# Direct GitHub Commit/Branch Reference in Package Install

## What it is

Installing packages directly from GitHub refs (`github:owner/repo#commit` or `git+https://github.com/owner/repo`) in CI workflows bypasses the package registry's integrity checks. The installed code is not subject to npm's provenance verification, signature validation, or audit scanning.

## How it's exploited

In the TanStack/Mistral supply chain attack (May 2025), malicious code was delivered through `optionalDependencies` pointing to GitHub commit refs:

```json
{
  "optionalDependencies": {
    "@anthropic-ai/tokenizer": "github:nicolo-ribaudo/chokidar-fix#main"
  }
}
```

This bypassed npm's integrity checks entirely. The GitHub repo contained a `postinstall` script that exfiltrated credentials. Because it was installed from a commit ref rather than the registry, npm audit could not flag it and provenance checks did not apply.

The same pattern in a workflow `run:` block:

```yaml
- run: npm install github:malicious-owner/legit-looking-name#abc123f
```

## How to fix

Always install from the package registry:

```yaml
# Before (vulnerable)
- run: npm install github:owner/repo#commit

# After (safe)
- run: npm install @scope/package@1.2.3
```

If you must use GitHub sources, pin to a full SHA and verify the repository:

```yaml
- run: npm install github:owner/repo#abc123def456789...  # full 40-char SHA
```

## Why it matters

Package registries provide integrity guarantees: checksums, provenance attestations, vulnerability scanning, and immutable versions. GitHub refs provide none of these. A ref can be force-pushed, a branch can be rebased, and a repository can be transferred to a new owner, all silently changing what gets installed.

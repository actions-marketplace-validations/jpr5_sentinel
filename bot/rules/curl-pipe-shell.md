# Remote Script Piped to Shell

## What it is

Piping a remote script directly to a shell interpreter (`curl ... | bash`) executes whatever the server returns, with no integrity verification. The remote endpoint is mutable -- the script can change between when you tested it and when CI runs it. A compromised CDN, DNS hijack, or malicious maintainer can serve arbitrary code.

## How it's exploited

```yaml
# Attacker compromises the remote endpoint or performs DNS hijack
- run: curl -fsSL https://example.com/install.sh | bash
```

The returned script runs with the full permissions of the CI job, including access to secrets and the ability to modify build outputs.

## How to fix

Download the script, verify its checksum, then execute:

```yaml
# Before (vulnerable)
- run: curl -fsSL https://example.com/install.sh | bash

# After (safe)
- run: |
      curl -fsSL -o install.sh https://example.com/install.sh
      echo "abc123...expected_sha256  install.sh" | sha256sum -c -
      bash install.sh
```

Better yet, replace the remote script with a pinned GitHub Action that does the same thing.

## Why it matters

Remote endpoints are mutable and unverified. Unlike SHA-pinned actions, there is no guarantee the content is the same as what you reviewed.

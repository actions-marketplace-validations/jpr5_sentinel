# Unpinned Actions -- Tag Reference Instead of SHA

## What it is

Actions referenced by tag (`uses: actions/checkout@v4`) point to a mutable Git reference. The tag can be force-pushed to point to a different commit at any time. An attacker who compromises the action's repository can update the tag to inject malicious code into every workflow that references it.

## How to fix

Pin actions to a full commit SHA and add a version comment:

```yaml
# Before (mutable tag)
- uses: actions/checkout@v4

# After (immutable SHA pin)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

Use Dependabot or Renovate to keep the SHA pins up to date:

```yaml
# .github/dependabot.yml
version: 2
updates:
    - package-ecosystem: github-actions
      directory: /
      schedule:
          interval: weekly
```

## Why it matters

SHA pins are immutable -- a specific commit cannot be changed after the fact. Tag references are mutable and can be silently replaced, making them a supply chain attack vector.

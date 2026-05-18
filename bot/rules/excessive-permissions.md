# Excessive Permissions on Read-Only Jobs

## What it is

A job has `contents: write` (or other write permissions) but no steps that appear to need write access. This gives every step in the job a more powerful token than necessary.

## How to fix

Restrict to read-only permissions:

```yaml
# Before (unnecessary write)
jobs:
    test:
        permissions:
            contents: write
        steps:
            - uses: actions/checkout@v4
            - run: npm test

# After (least privilege)
jobs:
    test:
        permissions:
            contents: read
        steps:
            - uses: actions/checkout@v4
            - run: npm test
```

## Why it matters

Over-privileged tokens increase the blast radius of a compromised step. A read-only job with a write token lets an attacker push code or modify releases if they compromise any step.

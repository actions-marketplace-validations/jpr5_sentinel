# Missing Top-Level Permissions Block

## What it is

Without a top-level `permissions` block, every job in the workflow inherits the default token permissions, which vary by repository setting but often include `contents: write`, `packages: write`, and other broad access. This violates the principle of least privilege.

## How to fix

Add a restrictive top-level permissions block and grant additional permissions only to jobs that need them:

```yaml
# Before (inherits broad defaults)
on: push
jobs:
    test:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
            - run: npm test

# After (explicit least-privilege)
on: push
permissions:
    contents: read

jobs:
    test:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
            - run: npm test

    deploy:
        permissions:
            contents: write
            id-token: write
        runs-on: ubuntu-latest
        steps:
            - run: deploy.sh
```

## Why it matters

A restrictive top-level permissions block limits the damage from any compromised step. Without it, every job has a broadly-privileged token by default.

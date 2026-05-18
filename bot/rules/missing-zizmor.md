# No zizmor Static Analysis Workflow

## What it is

zizmor is a static analysis tool purpose-built for GitHub Actions workflows. Without it, workflow security issues are only caught by manual review or external scanners. Adding a zizmor workflow catches many common misconfigurations automatically on every PR.

## How to fix

Add a zizmor workflow:

```yaml
# .github/workflows/security_zizmor.yml
name: zizmor
on:
    push:
        branches: [main]
        paths: [".github/workflows/**"]
    pull_request:
        paths: [".github/workflows/**"]

permissions:
    contents: read

jobs:
    zizmor:
        runs-on: ubuntu-latest
        timeout-minutes: 5
        steps:
            - uses: actions/checkout@v4
              with:
                  persist-credentials: false
            - uses: astral-sh/setup-uv@v4
            - run: uvx zizmor --format sarif . > results.sarif
              env:
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
            - uses: github/codeql-action/upload-sarif@v3
              with:
                  sarif_file: results.sarif
```

## Why it matters

Automated static analysis catches security regressions before they reach production. zizmor covers many of the same rules as this scanner and integrates with GitHub's code scanning UI.

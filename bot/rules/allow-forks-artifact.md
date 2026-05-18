# Fork-Produced Artifact Download in Privileged Context

## What it is

Downloading artifacts with `allow_forks: true` in a `workflow_run` context means you're processing content produced by untrusted fork code in a workflow that has access to base repository secrets. The artifact could contain modified build outputs, scripts, or data designed to exploit the privileged context.

## How to fix

Validate fork-produced artifacts before processing:

```yaml
# Before (blindly trusting fork artifacts)
- uses: actions/download-artifact@v4
  with:
      name: build-output
      github-token: ${{ secrets.GITHUB_TOKEN }}
      run-id: ${{ github.event.workflow_run.id }}
      allow_forks: true

# After (validate before use)
- uses: actions/download-artifact@v4
  with:
      name: build-output
      github-token: ${{ secrets.GITHUB_TOKEN }}
      run-id: ${{ github.event.workflow_run.id }}
      allow_forks: true
- run: |
      # Validate artifact contents before executing
      # Never execute scripts from fork artifacts
      # Only process expected file types (images, test results, etc.)
```

Better yet, avoid executing fork-produced content in privileged contexts entirely. Use label-gated workflows instead.

## Why it matters

This is the `workflow_run` + artifact version of the `pull_request_target` vulnerability. Fork-produced artifacts are untrusted input that should never be executed with base-branch secrets.

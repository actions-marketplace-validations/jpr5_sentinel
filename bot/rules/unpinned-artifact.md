# download-artifact Without Specific Name

## What it is

Using `actions/download-artifact` without specifying a `name:` downloads ALL artifacts from the workflow run. In workflows triggered by `workflow_run`, this may include artifacts uploaded by fork PRs, which can contain malicious content that gets executed in a privileged context.

## How to fix

Always specify the artifact name:

```yaml
# Before (downloads everything)
- uses: actions/download-artifact@v4

# After (downloads only the expected artifact)
- uses: actions/download-artifact@v4
  with:
      name: build-output
```

## Why it matters

Unnamed artifact downloads can pull in unexpected content from other jobs or fork-originated workflow runs, creating a path for code injection in privileged contexts.

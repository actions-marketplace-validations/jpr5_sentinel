# Hardcoded Secrets in Workflow Files

## What it is

API keys, tokens, and passwords hardcoded directly in workflow YAML files are visible to anyone who can read the repository. For public repos, this means anyone on the internet.

## Common patterns

- AWS access keys (`AKIA...`)
- GitHub personal access tokens (`ghp_...`, `github_pat_...`)
- Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- Slack webhooks (`hooks.slack.com/services/...`)
- API keys in environment variables set to literal values

## How to fix

Move secrets to GitHub Actions secrets and reference them:

```yaml
# Before (exposed)
env:
  API_KEY: "sk_live_abc123..."

# After (safe)
env:
  API_KEY: ${{ secrets.API_KEY }}
```

GitHub Actions secrets are encrypted at rest and only exposed to workflows at runtime. They are never logged and are masked in workflow output.

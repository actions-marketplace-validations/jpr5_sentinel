# Unscoped GitHub App Token

## What it is

When using `actions/create-github-app-token` without specifying permission scopes, the generated token inherits the full installation permissions of the GitHub App. This is typically far broader than what the workflow actually needs -- often including write access to code, issues, PRs, and admin settings.

## How to fix

Scope the token to only the permissions the job needs:

```yaml
# Before (inherits all installation permissions)
- uses: actions/create-github-app-token@v1
  with:
      app-id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}

# After (scoped to specific permissions)
- uses: actions/create-github-app-token@v1
  with:
      app-id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
      permission-contents: write
      permission-pull-requests: read
```

## Why it matters

Over-privileged tokens increase the blast radius if the token is leaked or a step is compromised. Scoping to minimum required permissions follows the principle of least privilege.

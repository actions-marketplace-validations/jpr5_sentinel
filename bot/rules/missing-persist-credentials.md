# Checkout Without persist-credentials: false

## What it is

By default, `actions/checkout` writes the GitHub token to the local `.git/config` file, where it remains accessible to every subsequent step in the job. Any script, dependency, or action that runs later can read this token and use it to make authenticated API calls or push to the repository.

## How it's exploited

A compromised dependency or malicious post-install script reads the token from `.git/config`:

```bash
cat .git/config | grep "url.*x-access-token"
```

The token typically has `contents: write` permission, allowing the attacker to push code, create releases, or modify branch protection settings.

## How to fix

Add `persist-credentials: false` to every checkout step:

```yaml
# Before (token persists in .git/config)
- uses: actions/checkout@v4

# After (token is not stored)
- uses: actions/checkout@v4
  with:
      persist-credentials: false
```

If a later step needs to push, configure credentials explicitly and immediately before the push, rather than relying on the persisted checkout token.

## Why it matters

The persisted token expands the attack surface of your entire CI job. Every step after checkout -- including third-party actions and dependency install scripts -- has implicit access to repository write credentials.

# git config --global With Credentials

## What it is

Using `git config --global` to set URL rewrite rules or credentials writes them to `~/.gitconfig`, making them accessible to every git operation in the entire runner session -- not just the current repository clone.

## How to fix

Use `--local` to scope credentials to the repository:

```yaml
# Before (global -- visible to all git operations)
- run: |
      git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"

# After (local -- scoped to this repo)
- run: |
      git config --local url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
```

## Why it matters

Global git config persists beyond the current checkout. Other actions, scripts, or submodules in the same job can use the credentials for unintended operations.

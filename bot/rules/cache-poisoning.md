# Cache Poisoning via Fork-Controllable Keys

## What it is

When cache keys contain fork-controllable references like `github.head_ref` or `github.event.pull_request.head.ref`, an attacker can craft a branch name that collides with a legitimate cache key. This lets them inject malicious content into the cache that will be restored by subsequent runs on trusted branches.

## How it's exploited

```yaml
- uses: actions/cache@v4
  with:
      key: build-${{ github.head_ref }}-${{ hashFiles('**/package-lock.json') }}
      path: node_modules
```

An attacker creates a fork branch named `main` (matching the base branch key), poisons the cache with modified `node_modules`, and subsequent runs on the real `main` branch restore the tainted cache.

## How to fix

Use `hashFiles()` for cache keys instead of branch refs:

```yaml
# Before (fork-controllable key)
- uses: actions/cache@v4
  with:
      key: build-${{ github.head_ref }}-${{ hashFiles('**/package-lock.json') }}
      path: node_modules

# After (content-addressed key)
- uses: actions/cache@v4
  with:
      key: build-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
      path: node_modules
```

For workflows that run on PR triggers, use `github.ref` with a fork-isolated prefix:

```yaml
key: pr-${{ github.event.number }}-${{ hashFiles('**/package-lock.json') }}
```

## Why it matters

Cache poisoning is a persistent attack -- the tainted cache outlives the malicious PR and affects all subsequent builds until the cache key changes.

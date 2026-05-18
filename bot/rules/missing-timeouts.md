# Job Without timeout-minutes

## What it is

Jobs without `timeout-minutes` use the GitHub Actions default of 360 minutes (6 hours). A hung job, infinite loop, or crypto-mining attack can consume runner minutes for hours before being killed.

## How to fix

Add a timeout appropriate for the job:

```yaml
# Before (6-hour default)
jobs:
    test:
        runs-on: ubuntu-latest
        steps:
            - run: npm test

# After (reasonable timeout)
jobs:
    test:
        runs-on: ubuntu-latest
        timeout-minutes: 15
        steps:
            - run: npm test
```

## Why it matters

Explicit timeouts limit resource waste from hung jobs and reduce the window for abuse on compromised runners.

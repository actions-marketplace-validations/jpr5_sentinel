# Self-Hosted Runner Exposed to Fork PRs

## What it is

When a workflow uses `pull_request` or `pull_request_target` triggers and runs on self-hosted runners, any fork contributor can execute arbitrary code on your infrastructure. Unlike GitHub-hosted runners, self-hosted runners are not ephemeral -- they persist between runs, sharing filesystems, credentials, and network access.

## How it's exploited

An attacker forks the repo, modifies workflow files or test scripts to include malicious commands, and opens a PR. The self-hosted runner executes their code with access to:

- The runner's filesystem (other repos, cached secrets)
- The host's network (internal services, databases)
- Any credentials or tools installed on the machine

## How to fix

Use GitHub-hosted runners for workflows that respond to fork PRs:

```yaml
# Before (vulnerable)
on: pull_request
jobs:
    test:
        runs-on: self-hosted
        steps:
            - uses: actions/checkout@v4
            - run: npm test

# After (safe)
on: pull_request
jobs:
    test:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v4
            - run: npm test
```

If you must use self-hosted runners, gate the trigger to only run on maintainer-applied labels:

```yaml
on:
    pull_request:
        types: [labeled]
```

## Why it matters

Self-hosted runners are persistent infrastructure. A compromised runner can attack your internal network, steal credentials from other projects, or establish long-term persistence.

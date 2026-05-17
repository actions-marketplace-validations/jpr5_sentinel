# Dangerous Triggers -- pull_request_target with Fork Code Checkout

## What it is

The `pull_request_target` trigger runs with the BASE branch's secrets and write permissions, but can be tricked into checking out and executing FORK code. This gives any fork contributor access to your repository secrets.

## How it's exploited

```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: npm test  # runs FORK code with BASE secrets
```

An attacker forks the repo, modifies `package.json` to add a `pretest` script that exfiltrates secrets, opens a PR, and the workflow runs their code with your secrets.

## How to fix

- Use `pull_request` trigger instead (runs with fork's limited permissions)
- If you must use `pull_request_target`, never checkout the PR head
- If you need PR head code, use a two-workflow pattern: first workflow labels/approves, second runs code only after maintainer approval

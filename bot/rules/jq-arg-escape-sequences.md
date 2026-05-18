# jq --arg Escape Sequences

## What it is

`jq --arg name value` treats `value` as a raw literal string. Backslash escape sequences like `\n`, `\t`, and `\\` are **not** interpreted -- they become literal backslash followed by the character. This means `jq --arg msg "line1\nline2"` produces a string containing the five characters `l`, `i`, `n`, `e`, `1`, `\`, `n`, `l`, `i`, `n`, `e`, `2` rather than two lines separated by a newline.

## The problem

```yaml
env:
  BODY: ${{ github.event.pull_request.body }}
run: |
  jq -nc --arg msg "Build succeeded\nCommit: $COMMIT_SHA" '{text: $msg}'
```

The author expects `\n` to produce a newline in the JSON output. Instead, jq emits the literal characters `\n` inside the string. The resulting Slack message, email, or log entry shows `Build succeeded\nCommit: abc123` on a single line instead of two lines.

This commonly happens when CI hardening replaces direct `${{ }}` usage with `env:` var indirection. The fix author moves values into `--arg` (correctly preventing injection) but then uses `\n` in the jq argument string, expecting it to behave like a C or JSON escape. It doesn't -- `--arg` is not `--argjson`.

## How to fix

**Option 1: Bash ANSI-C quoting with `$'...'`**

```yaml
run: |
  jq -nc --arg msg $'Build succeeded\nCommit: '"$COMMIT_SHA" '{text: $msg}'
```

Bash interprets `\n` inside `$'...'` as a real newline before passing the value to jq.

**Option 2: Use `--argjson` with a pre-escaped JSON string**

```yaml
run: |
  jq -nc --argjson msg '"Build succeeded\nCommit: '"$COMMIT_SHA"'"' '{text: $msg}'
```

`--argjson` parses its value as JSON, so JSON escape sequences like `\n` are interpreted. Note the extra quoting required to produce a valid JSON string.

**Option 3: Use a multi-line variable**

```yaml
env:
  MSG: |
    Build succeeded
    Commit: ${{ github.sha }}
run: |
  jq -nc --arg msg "$MSG" '{text: $msg}'
```

The YAML block scalar `|` preserves real newlines. `--arg` passes them through correctly because they are actual newline characters, not escape sequences.

## Why this matters

The workflow won't fail -- jq exits 0 and produces valid JSON. But the output contains literal `\n` text instead of newlines, causing silent data corruption. Downstream consumers (Slack messages, PR comments, release notes, log aggregators) display garbled single-line text instead of the intended multi-line format. These failures are hard to debug because everything looks correct in the workflow logs and the JSON is technically valid.

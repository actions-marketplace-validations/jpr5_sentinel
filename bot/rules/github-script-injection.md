# GitHub Script Injection

## What it is

The same injection vulnerability as shell injection, but in JavaScript context. When `${{ }}` expressions containing attacker-controlled values are interpolated inside `actions/github-script`'s `script:` block, the value is pasted into JavaScript code.

## How it's exploited

```yaml
- uses: actions/github-script@v7
  with:
    script: |
      const title = "${{ github.event.pull_request.title }}";
      console.log(title);
```

A PR title containing `"; process.env.GITHUB_TOKEN; "` leaks the token.

## How to fix

Use `context.payload` to access event data safely:

```yaml
- uses: actions/github-script@v7
  with:
    script: |
      const title = context.payload.pull_request.title;
      console.log(title);
```

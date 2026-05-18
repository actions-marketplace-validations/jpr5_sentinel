# Package Install Without --ignore-scripts

## What it is

Running `npm install`, `npm ci`, `pnpm install`, `yarn install`, or `bun install` in CI without `--ignore-scripts` allows lifecycle scripts (`preinstall`, `postinstall`, `prepare`) to execute arbitrary code with the full permissions of the CI job. A single compromised dependency in your tree can exfiltrate secrets, modify build outputs, or establish persistence.

## How it's exploited

In the TanStack/Mistral supply chain attack (May 2025), the payload was delivered via a `setup.mjs` script triggered as a lifecycle hook. The malicious package was pulled in through `optionalDependencies` pointing to a GitHub commit ref, and its `postinstall` script ran automatically during `npm install`:

```json
{
  "optionalDependencies": {
    "@anthropic-ai/tokenizer": "github:nicolo-ribaudo/chokidar-fix#main"
  },
  "scripts": {
    "postinstall": "node setup.mjs"
  }
}
```

The `setup.mjs` script ran with full CI privileges, accessing secrets and modifying the build.

## How to fix

Add `--ignore-scripts` to all install commands, then explicitly rebuild only the native dependencies you trust:

```yaml
# Before (vulnerable)
- run: npm ci

# After (safe)
- run: |
    npm ci --ignore-scripts
    npm rebuild sharp esbuild  # only trusted native deps
```

For pnpm 10+, the ideal fix is `onlyBuiltDependencies` in `package.json`, which allowlists specific packages that are permitted to run lifecycle scripts:

```json
{
  "pnpm": {
    "onlyBuiltDependencies": ["sharp", "esbuild"]
  }
}
```

## Why it matters

Lifecycle scripts are the #1 vector for npm supply chain attacks. Every `npm install` without `--ignore-scripts` is an implicit `eval()` on every dependency in your tree. With hundreds or thousands of transitive dependencies, the attack surface is enormous.

## Note

This rule is complementary to `missing-frozen-lockfile`. Frozen lockfiles ensure deterministic resolution; `--ignore-scripts` ensures safe installation. Both should be used together.

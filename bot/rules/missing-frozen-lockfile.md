# Package Install Without Lockfile Enforcement

## What it is

Running `npm install`, `pnpm install`, `yarn install`, `pip install`, `bundle install`, or other package managers in CI without lockfile enforcement means dependency resolution happens at install time. The versions installed may differ from what was tested locally, introducing untested code and potential supply chain attacks.

## How to fix

Use the lockfile-enforcing variant for each package manager:

```yaml
# JavaScript / TypeScript
- run: npm ci                              # not: npm install
- run: pnpm install --frozen-lockfile      # not: pnpm install
- run: yarn install --frozen-lockfile      # not: yarn install
- run: bun install --frozen-lockfile       # not: bun install

# Python
- run: pip install -r requirements.txt --require-hashes

# Ruby
- run: bundle install --frozen             # not: bundle install

# Rust
- run: cargo install --locked              # not: cargo install

# Go
- run: go mod download                     # not: go get

# PHP
- run: composer install                    # not: composer update
```

## Why it matters

Without lockfile enforcement, a compromised or yanked dependency version can silently enter your CI build. Lockfile enforcement ensures exact reproducibility between local development and CI.

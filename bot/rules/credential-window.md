# Credential Window -- Credentials Configured Far From Push

## What it is

When git credentials are configured (via `git config ... insteadOf` or `git remote set-url`) many steps before the actual `git push`, every intermediate step has access to the token. This unnecessarily widens the window during which a compromised action or script can steal the credentials.

## How it's exploited

```yaml
steps:
    - run: |
          git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
    - run: npm ci          # step 2 -- has access to token
    - run: npm test        # step 3 -- has access to token
    - run: npm run build   # step 4 -- has access to token
    - run: npm run lint    # step 5 -- has access to token
    - run: git push        # step 6 -- finally uses the token
```

Any of steps 2-5 (or their dependencies) can read the token from `~/.gitconfig` or the git remote URL.

## How to fix

Move credential configuration to immediately before the push:

```yaml
steps:
    - run: npm ci
    - run: npm test
    - run: npm run build
    - run: npm run lint
    - run: |
          git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
          git push
```

## Why it matters

Minimizing the credential window limits the blast radius of a compromised step. The token should only be available to the step that needs it.

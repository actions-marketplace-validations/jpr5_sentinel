# Secrets in Docker Build Args

## What it is

Docker build arguments (`--build-arg`) are embedded in the image layer metadata. Anyone who pulls the image can extract them with `docker history` or `docker inspect`. Passing secrets as build args makes them permanently visible in the image.

## How it's exploited

```yaml
- uses: docker/build-push-action@v5
  with:
      build-args: |
          NPM_TOKEN=${{ secrets.NPM_TOKEN }}
```

After pulling the image:

```bash
docker history --no-trunc <image> | grep NPM_TOKEN
```

The secret is visible in plaintext in the build history.

## How to fix

Use Docker BuildKit secrets instead of build args:

```yaml
# Before (secret in image layers)
- uses: docker/build-push-action@v5
  with:
      build-args: |
          NPM_TOKEN=${{ secrets.NPM_TOKEN }}

# After (secret mounted at build time only)
- uses: docker/build-push-action@v5
  with:
      secrets: |
          npm_token=${{ secrets.NPM_TOKEN }}
```

In the Dockerfile, access the secret via mount:

```dockerfile
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
```

## Why it matters

Build args are not secret -- they are recorded in image metadata. Anyone with access to the image (public registry, compromised pull) can extract every build arg value.

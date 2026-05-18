# Docker Image Using :latest Tag

## What it is

Docker images referenced with `:latest` (or no tag) point to a mutable reference. The image content can change at any time, making builds non-reproducible and vulnerable to tag-hijacking attacks.

## How to fix

Pin to a specific digest:

```yaml
# Before (mutable)
container:
    image: node:latest

# After (immutable)
container:
    image: node@sha256:abc123...
```

Or at minimum, pin to a specific version tag:

```yaml
container:
    image: node:20.11.1-alpine
```

## Why it matters

`:latest` is mutable and non-reproducible. A compromised registry or image maintainer can replace the image content, affecting all consumers immediately.

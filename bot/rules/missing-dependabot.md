# No Dependabot Configuration for GitHub Actions

## What it is

Without Dependabot configured for the `github-actions` ecosystem, your action version pins (both tag and SHA) go stale. You miss security patches, bug fixes, and the SHA pins needed to stay protected against tag-hijacking attacks.

## How to fix

Add a Dependabot configuration:

```yaml
# .github/dependabot.yml
version: 2
updates:
    - package-ecosystem: github-actions
      directory: /
      schedule:
          interval: weekly
```

## Why it matters

Dependabot automates the otherwise tedious process of keeping SHA pins current, ensuring your workflows get security updates promptly.

# Static AWS Credentials Instead of OIDC

## What it is

Using static AWS access keys (`aws-access-key-id` / `aws-secret-access-key`) in `configure-aws-credentials` means the credentials are long-lived and don't auto-expire. If leaked via logs, compromised dependencies, or repo access, they remain valid until manually rotated.

## How to fix

Switch to OIDC federation with an IAM role:

```yaml
# Before (static keys)
- uses: aws-actions/configure-aws-credentials@v4
  with:
      aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
      aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      aws-region: us-east-1

# After (OIDC -- short-lived, auto-expiring credentials)
permissions:
    id-token: write
    contents: read

steps:
    - uses: aws-actions/configure-aws-credentials@v4
      with:
          role-to-assume: arn:aws:iam::123456789:role/GitHubActionsRole
          aws-region: us-east-1
```

OIDC tokens are scoped to the workflow run, expire automatically, and require no stored secrets.

## Why it matters

Static credentials are the #1 cause of AWS account compromise. OIDC federation eliminates long-lived secrets entirely and scopes access to specific repos, branches, and workflows.

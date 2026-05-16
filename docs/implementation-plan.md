# Implementation Plan

## Task 1: Core infrastructure
- `lib/finding.rb` — Struct
- `lib/workflow.rb` — YAML parser + helpers
- `lib/rule_engine.rb` — loads rules, runs them
- `lib/rules/base.rb` — interface

## Task 2: Clients
- `lib/github_client.rb` — API fetch
- `lib/local_client.rb` — filesystem read

## Task 3: Formatters
- `lib/formatter/terminal.rb`
- `lib/formatter/json.rb`

## Task 4: Scanner orchestrator + CLI
- `lib/scanner.rb` — ties it all together
- `bin/sentinel` — entry point with optparse

## Task 5: Rules batch 1 (critical)
- Rules 1-4: unpinned_actions, shell_injection_expr, shell_injection_jq, dangerous_triggers

## Task 6: Rules batch 2 (high)
- Rules 5-10: missing_persist_creds, credential_window, static_aws_creds, unscoped_app_token, docker_build_arg_secrets, build_publish_same_job

## Task 7: Rules batch 3 (medium + low)
- Rules 11-20: missing_permissions, git_config_global, missing_timeouts, missing_env_protection, allow_forks_artifact, missing_frozen_lockfile, unpinned_docker_image, overly_broad_triggers, missing_dependabot, missing_zizmor

## Task 8: Test against 3 public repos
- Run against vercel/next.js, facebook/react, kubernetes/kubernetes
- Manual review of findings
- Calibrate rules

## Task 9: Create GitHub repo
- Push to CopilotKit/sentinel

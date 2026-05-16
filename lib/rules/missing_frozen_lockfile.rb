module Rules
    class MissingFrozenLockfile < Base
        def name = "missing-frozen-lockfile"
        def description = "Package install without lockfile enforcement"
        def severity = :medium

        # JavaScript/TypeScript
        # npm install without --ci (or use npm ci instead)
        NPM_INSTALL = /\bnpm\s+install\b/
        NPM_SAFE    = /--ci\b|\bnpm\s+ci\b/

        # pnpm install without --frozen-lockfile
        PNPM_INSTALL = /\bpnpm\s+install\b/
        PNPM_SAFE    = /--frozen-lockfile/

        # yarn install without --frozen-lockfile or --immutable
        YARN_INSTALL = /\byarn\s+install\b/
        YARN_SAFE    = /--frozen-lockfile|--immutable/

        # bun install without --frozen-lockfile
        BUN_INSTALL = /\bbun\s+install\b/
        BUN_SAFE    = /--frozen-lockfile/

        # Python
        # pip install / pip3 install with package names (not local installs, not -r)
        PIP_INSTALL  = /\b(?:pip3?|uv\s+pip)\s+install\b/
        PIP_SAFE     = /-r\b|--requirement\b|-c\b|--constraint\b|--require-hashes/
        PIP_LOCAL    = /\binstall\s+(?:-e\s+)?\.(?:\s|$|\[)/

        # Ruby
        # bundle install (or bare bundle) without --frozen or --deployment
        BUNDLE_INSTALL = /\bbundle\b(?:\s+install\b)?/
        BUNDLE_SAFE    = /--frozen|--deployment|BUNDLE_FROZEN\s*=\s*(?:true|1)/
        # Avoid matching unrelated bundle subcommands
        BUNDLE_OTHER   = /\bbundle\s+(?:exec|add|update|show|list|info|outdated|check|config|lock|cache|clean|console|open|gem|platform|env|doctor|viz|version|init|binstubs|pristine|plugin)\b/

        # Go
        # go get in CI is non-deterministic; suggest go mod download
        GO_GET = /\bgo\s+get\b/

        # Rust
        # cargo install without --locked
        CARGO_INSTALL = /\bcargo\s+install\b/
        CARGO_SAFE    = /--locked/

        # PHP
        # composer update resolves fresh, ignoring lockfile
        COMPOSER_UPDATE = /\bcomposer\s+update\b/

        CHECKS = [
            {
                match: NPM_INSTALL,
                safe: NPM_SAFE,
                message: "npm install without lockfile enforcement — dependency resolution may differ from tested versions",
                fix: "Use `npm ci` instead of `npm install`",
            },
            {
                match: PNPM_INSTALL,
                safe: PNPM_SAFE,
                message: "pnpm install without --frozen-lockfile — dependency resolution may differ from tested versions",
                fix: "Use `pnpm install --frozen-lockfile`",
            },
            {
                match: YARN_INSTALL,
                safe: YARN_SAFE,
                message: "yarn install without lockfile enforcement — dependency resolution may differ from tested versions",
                fix: "Use `yarn install --frozen-lockfile` or `yarn install --immutable`",
            },
            {
                match: BUN_INSTALL,
                safe: BUN_SAFE,
                message: "bun install without --frozen-lockfile — dependency resolution may differ from tested versions",
                fix: "Use `bun install --frozen-lockfile`",
            },
            {
                match: PIP_INSTALL,
                safe: PIP_SAFE,
                safe_alt: PIP_LOCAL,
                message: "pip install with unpinned packages — no lockfile or constraints file ensuring reproducibility",
                fix: "Use `pip install -r requirements.txt --require-hashes` or a constraints file",
            },
            {
                match: BUNDLE_INSTALL,
                safe: BUNDLE_SAFE,
                skip: BUNDLE_OTHER,
                message: "bundle install without --frozen — Gemfile.lock may be modified during install",
                fix: "Use `bundle install --frozen` or `bundle install --deployment`",
            },
            {
                match: GO_GET,
                message: "go get in CI is non-deterministic — resolved versions may change between runs",
                fix: "Use `go mod download` instead (uses go.sum for verification)",
            },
            {
                match: CARGO_INSTALL,
                safe: CARGO_SAFE,
                message: "cargo install without --locked — Cargo.lock will be ignored and dependencies re-resolved",
                fix: "Use `cargo install --locked`",
            },
            {
                match: COMPOSER_UPDATE,
                message: "composer update in CI resolves fresh dependencies, ignoring composer.lock",
                fix: "Use `composer install` instead (respects composer.lock)",
            },
        ]

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                stripped = line.strip
                next if stripped.start_with?("#")

                CHECKS.each do |chk|
                    next unless line.match?(chk[:match])
                    next if chk[:skip] && line.match?(chk[:skip])
                    next if chk[:safe] && line.match?(chk[:safe])
                    next if chk[:safe_alt] && line.match?(chk[:safe_alt])

                    # For npm install, also check if the line contains "npm ci" separately
                    next if chk[:match] == NPM_INSTALL && line.match?(/\bnpm\s+ci\b/)

                    findings << finding(workflow,
                        line: i + 1,
                        code: stripped,
                        message: chk[:message],
                        fix: chk[:fix]
                    )
                end
            end

            findings
        end
    end
end

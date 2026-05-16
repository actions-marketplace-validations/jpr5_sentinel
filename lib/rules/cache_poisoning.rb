module Rules
    class CachePoisoning < Base
        def name = "cache-poisoning"
        def description = "Cache key uses mutable, fork-controllable reference"
        def severity = :medium

        CACHE_ACTIONS = %w[
            actions/cache
            actions/cache/restore
            actions/cache/save
        ].freeze

        # Fork-controllable refs that should never appear in cache keys
        DANGEROUS_KEY_PATTERNS = [
            /\$\{\{\s*github\.head_ref\s*\}\}/,
            /\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}/,
        ].freeze

        # github.ref on pull_request triggers resolves to the PR merge ref
        GITHUB_REF_PATTERN = /\$\{\{\s*github\.ref\s*\}\}/

        PR_TRIGGERS = %w[pull_request pull_request_target].freeze

        def check(workflow)
            findings = []
            has_pr_trigger = pr_triggered?(workflow)

            workflow.uses_actions.each do |action|
                uses = action[:uses]
                next unless CACHE_ACTIONS.any? { |ca| uses&.start_with?(ca) }

                step = action[:step]
                key_value = step.dig("with", "key")
                next unless key_value

                # Check for directly dangerous patterns
                DANGEROUS_KEY_PATTERNS.each do |pattern|
                    if key_value.match?(pattern)
                        findings << finding(workflow,
                            line: action[:line] || 0,
                            code: "key: #{key_value}",
                            message: "Cache key contains fork-controllable reference — risk of cache poisoning",
                            fix: "Use hashFiles() for cache keys, not branch refs. Consider prefixing fork PR cache keys."
                        )
                        break
                    end
                end

                # Check for github.ref on PR-triggered workflows
                if has_pr_trigger && key_value.match?(GITHUB_REF_PATTERN)
                    findings << finding(workflow,
                        line: action[:line] || 0,
                        code: "key: #{key_value}",
                        message: "Cache key uses github.ref on pull_request trigger — resolves to mutable PR merge ref",
                        fix: "Use hashFiles() for cache keys, not branch refs. Consider prefixing fork PR cache keys."
                    )
                end
            end

            findings
        end

        private

        def pr_triggered?(workflow)
            triggers = workflow.triggers
            case triggers
            when Hash
                triggers.keys.any? { |t| PR_TRIGGERS.include?(t.to_s) }
            when Array
                triggers.any? { |t| PR_TRIGGERS.include?(t.to_s) }
            when String
                PR_TRIGGERS.include?(triggers)
            else
                false
            end
        end
    end
end

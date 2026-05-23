require_relative "concerns/guard_patterns"

module Rules
    class GithubScriptInjection < Base
        include GuardPatterns

        def name = "github-script-injection"
        def description = "Attacker-controllable ${{ }} expression in actions/github-script"
        def severity = :critical

        DANGEROUS_EXPR_PATTERN = /\$\{\{\s*(#{DANGEROUS_CONTEXTS.map { |c| Regexp.escape(c) }.join('|')})/
        INPUT_EXPR_PATTERN = /\$\{\{\s*((?:inputs|github\.event\.inputs)\.[^\s}]+)/

        def check(workflow)
            findings = []
            safe_triggers = safe_trigger_only?(workflow)

            workflow.raw_lines.each_with_index do |line, idx|
                line_num = idx + 1
                next if line.strip.start_with?('#')
                next unless in_github_script_block?(workflow, line_num)

                has_dangerous = line.match?(DANGEROUS_EXPR_PATTERN)
                has_input = line.match?(INPUT_EXPR_PATTERN)
                next unless has_dangerous || has_input

                guarded = guarded_by_safe_event?(workflow, line_num)

                # INPUT expressions (inputs.*) are user-controlled even on
                # safe-trigger-only workflows, so they always fire.
                if has_input
                    match = line.match(INPUT_EXPR_PATTERN)
                    if match
                        findings << finding(workflow,
                            line: line_num,
                            code: line.strip,
                            message: "Attacker-controllable expression \${{ #{match[1]} }} in actions/github-script — JavaScript injection risk",
                            fix: "Pass input via env: block and reference as process.env.VAR"
                        )
                    end
                end

                # DANGEROUS expressions respect both safe_trigger_only? and
                # event guards — they are only exploitable from unsafe triggers.
                if has_dangerous && !safe_triggers && !guarded
                    match = line.match(DANGEROUS_EXPR_PATTERN)
                    if match
                        findings << finding(workflow,
                            line: line_num,
                            code: line.strip,
                            message: "Attacker-controllable expression \${{ #{match[1]} }} in actions/github-script — JavaScript injection risk",
                            fix: "Use context.payload instead: context.payload.pull_request.title"
                        )
                    end
                end
            end

            findings
        end

        private

        # All valid GHA step-level properties — used as scan boundaries.
        STEP_KEYS = /(?:id|if|name|uses|run|working-directory|shell|with|env|continue-on-error|timeout-minutes|permissions|secrets)/

        def in_github_script_block?(workflow, target_line)
            # Scan backward with no cap — use step keys as hard boundaries.
            (target_line - 1).downto(0) do |i|
                content = workflow.raw_lines[i]
                next unless content

                if content.match?(/^\s+script:\s*[\|>]?\s*$/) || content.match?(/^\s+script:\s+\S/)
                    # Found a script: key. Now scan upward from here with no cap,
                    # looking for uses: actions/github-script. Stop at any step key
                    # that is NOT with:, env:, or uses: (those can appear between
                    # uses: and script:).
                    i.downto(0) do |j|
                        step_line = workflow.raw_lines[j]
                        next unless step_line
                        return true if step_line.match?(/uses:\s*actions\/github-script/)
                        # Step boundary: any step key other than with:/env:/uses:
                        # on a list-item line means a different step.
                        break if step_line.match?(/^\s+-\s+#{STEP_KEYS}:\s/)
                        # Non-list step keys that are NOT with:/env:/uses: are boundaries
                        if step_line.match?(/^\s+#{STEP_KEYS}:\s/) && !step_line.match?(/^\s+(with|env|uses):/)
                            break
                        end
                    end
                    return false
                end

                # Any step-level key (other than with:/env: sub-keys) is a boundary.
                # A list-item step key means a different step entirely.
                break if content.match?(/^\s+-\s+#{STEP_KEYS}:\s/)
                # A non-list step key that is NOT with:/env: is a boundary
                if content.match?(/^\s+#{STEP_KEYS}:\s/) && !content.match?(/^\s+(with|env|script):/)
                    break
                end
            end

            false
        end
    end
end

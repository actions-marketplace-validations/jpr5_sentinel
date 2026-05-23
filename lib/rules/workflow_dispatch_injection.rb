require_relative "concerns/guard_patterns"

module Rules
    class WorkflowDispatchInjection < Base
        include GuardPatterns

        def name = "workflow-dispatch-injection"
        def description = "User-controlled workflow_dispatch input in run: block"
        def severity = :high

        PATTERN = /\$\{\{\s*(?:inputs\.|github\.event\.inputs\.)/

        # All valid GHA step-level properties (excluding run:, which is handled separately).
        STEP_KEYS = /(?:id|if|name|uses|working-directory|shell|with|env|continue-on-error|timeout-minutes|permissions|secrets)/

        # NOTE: This rule intentionally does NOT use safe_trigger_only? because
        # dispatch inputs are user-controlled. workflow_dispatch IS in SAFE_TRIGGERS
        # for other rules, but this rule specifically targets ${{ inputs.* }} in
        # run blocks — those inputs are always attacker-controlled.

        def check(workflow)
            findings = []

            workflow.lines_of(PATTERN).each do |line_num|
                line = workflow.line_content(line_num)
                next if line.strip.start_with?('#')
                next unless in_run_block?(workflow, line_num)
                match = line.match(/\$\{\{\s*((?:inputs|github\.event\.inputs)\.[^\s}]+)/)
                next unless match

                findings << finding(workflow,
                    line: line_num,
                    code: workflow.line_content(line_num).strip,
                    message: "User-controlled input ${{ #{match[1]} }} in run: block — shell injection risk",
                    fix: "Move to env: block and reference as $ENV_VAR"
                )
            end

            findings
        end

        private

        # Determines whether the line at target_line is inside a `run:` block.
        # Scans backwards with no lookback cap to find the nearest step-level
        # YAML property key. If that key is `run:`, the line is in a shell
        # context. If it's any other step key (with:, uses:, env:, etc.),
        # the line is NOT in a shell context.
        #
        # Uses STEP_KEYS to recognize all valid GHA step properties as
        # boundaries, preventing false positives when a `run:` from a
        # PREVIOUS step is encountered during backward scan.
        def in_run_block?(workflow, target_line)
            target_content = workflow.raw_lines[target_line - 1]
            return false unless target_content

            (target_line - 1).downto(0) do |i|
                content = workflow.raw_lines[i]
                next unless content

                # Direct `run:` key (not on a list item line)
                if content.match?(/^\s+run:\s*[\|>]?\s*$/) || content.match?(/^\s+run:\s+\S/)
                    return !nested_under_with?(workflow, i)
                end
                # `run:` on a list item line: `- run: |`
                if content.match?(/^\s+-\s+run:\s*[\|>]?\s*$/) || content.match?(/^\s+-\s+run:\s+\S/)
                    return true
                end

                # Any other step-level key acts as a boundary — we're NOT in a run block.
                # This catches with:, uses:, env:, name:, if:, id:, working-directory:,
                # shell:, continue-on-error:, timeout-minutes:, permissions:, secrets:.
                return false if content.match?(/^\s+#{STEP_KEYS}:\s/)
                return false if content.match?(/^\s+-\s+#{STEP_KEYS}:\s/)

                # steps: key means we've left all steps — not in a run block
                return false if content.match?(/^\s+steps:\s*$/)
            end
            false
        end

        # Checks whether the `run:` key at line_index is nested inside a `with:`
        # block (i.e. it's an action parameter named "run", not a step-level
        # shell command). The discriminator is YAML indentation: a step-level
        # `run:` shares indent with `with:`/`uses:`/etc., while a nested `run:`
        # is indented deeper than its parent `with:`.
        def nested_under_with?(workflow, line_index)
            run_line = workflow.raw_lines[line_index]
            run_indent = run_line[/^\s*/].length

            (line_index - 1).downto(0) do |i|
                content = workflow.raw_lines[i]
                next unless content

                line_indent = content[/^\s*/].length

                # If we hit a `with:` at less indent, this run: is nested inside it.
                return true if line_indent < run_indent && content.match?(/^\s+with:\s/)

                # If we hit any step-level key at equal or less indent, this run:
                # is at step level (not nested).
                return false if line_indent <= run_indent && content.match?(/^\s+#{STEP_KEYS}:\s/)
                return false if line_indent <= run_indent && content.match?(/^\s+-\s+#{STEP_KEYS}:\s/)

                # Step boundary (list item start at equal or less indent) — stop.
                return false if content.match?(/^\s+-\s/) && line_indent <= run_indent

                # steps: key means we've left all steps — not nested.
                return false if content.match?(/^\s+steps:\s*$/)
            end
            false
        end
    end
end

require_relative "concerns/guard_patterns"

module Rules
    class WorkflowDispatchInjection < Base
        include GuardPatterns

        def name = "workflow-dispatch-injection"
        def description = "User-controlled workflow_dispatch input in run: block"
        def severity = :high

        PATTERN = /\$\{\{\s*(?:inputs\.|github\.event\.inputs\.)/

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

        def in_run_block?(workflow, target_line)
            target_content = workflow.raw_lines[target_line - 1]
            target_indent = target_content ? target_content[/^\s*/].length : 0

            (target_line - 1).downto([target_line - 20, 0].max) do |i|
                content = workflow.raw_lines[i]
                next unless content

                return true if content.match?(/^\s+run:\s*[\|>]?\s*$/) || content.match?(/^\s+run:\s+\S/)
                return true if content.match?(/^\s+-\s+run:\s*[\|>]?\s*$/) || content.match?(/^\s+-\s+run:\s+\S/)

                if content.match?(/^\s+(uses|with|if|id|name|env):/) || content.match?(/^\s+-\s+name:/)
                    line_indent = content[/^\s*/].length
                    return false if target_indent <= line_indent + 2
                end
            end
            false
        end
    end
end

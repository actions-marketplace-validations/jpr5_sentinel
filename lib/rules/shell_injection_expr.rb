module Rules
    class ShellInjectionExpr < Base
        def name = "shell-injection-expr"
        def description = "Attacker-controllable ${{ }} expression in run: block"
        def severity = :critical

        DANGEROUS_CONTEXTS = %w[
            github.event.pull_request.title
            github.event.pull_request.body
            github.event.pull_request.head.ref
            github.event.pull_request.head.label
            github.event.issue.title
            github.event.issue.body
            github.event.comment.body
            github.event.review.body
            github.event.discussion.title
            github.event.discussion.body
            github.event.workflow_run.head_branch
            github.head_ref
            github.actor
            github.triggering_actor
        ].freeze

        PATTERN = /\$\{\{\s*(#{DANGEROUS_CONTEXTS.map { |c| Regexp.escape(c) }.join('|')})/

        def check(workflow)
            findings = []
            workflow.lines_of(PATTERN).each do |line_num|
                line = workflow.line_content(line_num)
                next unless in_run_block?(workflow, line_num)

                match = line.match(PATTERN)
                next unless match

                findings << finding(workflow,
                    line: line_num,
                    code: line.strip,
                    message: "Attacker-controllable expression ${{ #{match[1]} }} in run: block — shell injection risk",
                    fix: "Move to env: block and reference as $ENV_VAR in the shell"
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

                # Stop at step-level keys, but only if the target line is at or
                # shallower than this key's indent (meaning the target is a sibling
                # or child of this key, not content of a deeper run: block).
                if content.match?(/^\s+(uses|with|if|id|name|env):/) || content.match?(/^\s+-\s+name:/)
                    line_indent = content[/^\s*/].length
                    return false if target_indent <= line_indent + 2
                end
            end
            false
        end
    end
end

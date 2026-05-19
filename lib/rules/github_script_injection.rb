require_relative "concerns/guard_patterns"

module Rules
    class GithubScriptInjection < Base
        include GuardPatterns

        def name = "github-script-injection"
        def description = "Attacker-controllable ${{ }} expression in actions/github-script"
        def severity = :critical

        PATTERN = /\$\{\{\s*(#{DANGEROUS_CONTEXTS.map { |c| Regexp.escape(c) }.join('|')})/

        def check(workflow)
            findings = []

            return [] if safe_trigger_only?(workflow)

            workflow.raw_lines.each_with_index do |line, idx|
                line_num = idx + 1
                next if line.strip.start_with?('#')
                next unless line.match?(PATTERN)
                next unless in_github_script_block?(workflow, line_num)
                next if guarded_by_safe_event?(workflow, line_num)

                stripped_line = strip_inline_comment(line)
                match = stripped_line.match(PATTERN)
                next unless match

                findings << finding(workflow,
                    line: line_num,
                    code: line.strip,
                    message: "Attacker-controllable expression ${{ #{match[1]} }} in actions/github-script — JavaScript injection risk",
                    fix: "Use context.payload instead: context.payload.pull_request.title"
                )
            end

            findings
        end

        private

        def in_github_script_block?(workflow, target_line)
            in_script = false
            script_indent = nil

            (target_line - 1).downto([target_line - 30, 0].max) do |i|
                content = workflow.raw_lines[i]
                next unless content

                if content.match?(/^\s+script:\s*[\|>]?\s*$/) || content.match?(/^\s+script:\s+\S/)
                    in_script = true
                    script_indent = content[/^\s*/].length
                    i.downto([i - 15, 0].max) do |j|
                        step_line = workflow.raw_lines[j]
                        next unless step_line
                        return true if step_line.match?(/uses:\s*actions\/github-script/)
                        break if step_line.match?(/^\s+-\s+(name|uses|run|if|id):/)
                    end
                    return false
                end

                if content.match?(/^\s+(uses|run|if|id|name|env|with):/) || content.match?(/^\s+-\s+(name|uses|run):/)
                    return false
                end
            end

            false
        end
    end
end

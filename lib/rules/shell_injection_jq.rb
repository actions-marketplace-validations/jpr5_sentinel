require_relative "concerns/guard_patterns"

module Rules
    class ShellInjectionJq < Base
        include GuardPatterns

        def name = "shell-injection-jq"
        def description = "Shell variable interpolated in double-quoted jq/curl JSON argument"
        def severity = :critical

        ATTACKER_ENV_VARS = %w[
            PR_TITLE PR_BODY PR_AUTHOR HEAD_REF ISSUE_TITLE ISSUE_BODY COMMENT_BODY
            PR_HEAD_REF BRANCH_NAME
        ].freeze

        JQ_PATTERN = /jq\s+([a-zA-Z-]+\s+)*--arg\s+\w+\s+"[^"]*\$\{/
        CURL_JSON_PATTERN = /curl\s.*-d\s+"[^"]*\$\{/

        def check(workflow)
            findings = []

            return [] if safe_trigger_only?(workflow)

            workflow.raw_lines.each_with_index do |line, i|
                line_num = i + 1
                next if line.strip.start_with?('#')
                next unless in_run_block?(workflow, line_num)
                next if guarded_by_safe_event?(workflow, line_num)

                check_line = strip_inline_comment(line)

                if check_line.match?(JQ_PATTERN)
                    var_match = check_line.match(/\$\{(\w+)\}/)
                    next unless var_match
                    var_name = var_match[1]
                    next unless potentially_attacker_controlled?(var_name)

                    findings << finding(workflow,
                        line: line_num,
                        code: line.strip,
                        message: "${#{var_name}} interpolated in double-quoted jq argument — $(command) executes via bash substitution",
                        fix: "Use jq --arg: jq -nc --arg #{var_name.downcase} \"$#{var_name}\" '{text: $#{var_name.downcase}}'"
                    )
                end

                if check_line.match?(CURL_JSON_PATTERN)
                    var_match = check_line.match(/\$\{(\w+)\}/)
                    next unless var_match
                    var_name = var_match[1]
                    next unless potentially_attacker_controlled?(var_name)

                    findings << finding(workflow,
                        line: line_num,
                        code: line.strip,
                        message: "${#{var_name}} interpolated in double-quoted curl JSON — command substitution risk",
                        fix: "Build JSON payload with jq -nc --arg instead of string interpolation"
                    )
                end
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

        def potentially_attacker_controlled?(var_name)
            ATTACKER_ENV_VARS.any? { |v| var_name.upcase == v } ||
                var_name.match?(/^(PR_|ISSUE_|COMMENT_)?(TITLE|BODY|HEAD_REF|BRANCH_NAME|COMMENT_BODY|AUTHOR)$/i)
        end
    end
end

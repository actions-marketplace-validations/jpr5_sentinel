module Rules
    class JqArgEscape < Base
        def name = "jq-arg-escape-sequences"
        def description = "jq --arg value contains backslash escape sequences that won't be interpreted"
        def severity = :medium

        PATTERN = /jq\s.*--arg\s+\w+\s+"[^"]*\\[nt\\][^"]*"/

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                next if line.strip.start_with?("#")
                next unless line.match?(PATTERN)

                findings << finding(workflow,
                    line: i + 1,
                    code: line.strip,
                    message: "jq --arg treats values as raw literals — \\n becomes literal backslash-n, not a newline",
                    fix: "Use real newlines via $'\\n' or multi-line variable, or use --argjson with pre-escaped JSON"
                )
            end

            findings
        end
    end
end

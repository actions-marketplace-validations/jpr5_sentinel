module Rules
    class IdeConfigInjection < Base
        def name = "ide-config-injection"
        def description = "Workflow writes to IDE/AI agent config files that auto-execute code"
        def severity = :critical

        WRITE_PATTERN = /(echo|cat|tee|printf|cp|mv|install|sed|>|>>).*\.(claude|vscode|cursor)\//

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                next if line.strip.start_with?("#")

                if line.match?(WRITE_PATTERN)
                    findings << finding(workflow,
                        line: i + 1,
                        code: line.strip,
                        message: "Workflow writes to IDE/AI config files — can execute arbitrary code on project open",
                        fix: "Remove IDE config file writes from workflows, or validate content before writing"
                    )
                end
            end

            findings
        end
    end
end

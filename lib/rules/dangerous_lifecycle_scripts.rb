module Rules
    class DangerousLifecycleScripts < Base
        def name = "dangerous-lifecycle-scripts"
        def description = "Package install without --ignore-scripts in workflow with secrets"
        def severity = :medium

        INSTALL_CMDS = [
            { match: /\bnpm\s+(install|ci)\b/, safe: /--ignore-scripts/, name: "npm" },
            { match: /\bpnpm\s+install\b/, safe: /--ignore-scripts/, name: "pnpm" },
            { match: /\byarn\s+install\b/, safe: /--ignore-scripts/, name: "yarn" },
            { match: /\byarn\b(?!\s+(exec|run|add|remove|why|info|install))/, safe: /--ignore-scripts/, name: "yarn" },
            { match: /\bbun\s+install\b/, safe: /--ignore-scripts|--no-scripts/, name: "bun" },
        ]

        def check(workflow)
            return [] unless workflow_has_secrets?(workflow)

            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                next if line.strip.start_with?("#")

                INSTALL_CMDS.each do |cmd|
                    next unless line.match?(cmd[:match])
                    next if line.match?(cmd[:safe])

                    findings << finding(workflow,
                        line: i + 1,
                        code: line.strip,
                        message: "#{cmd[:name]} install runs lifecycle scripts in a workflow with secrets — a compromised dependency can exfiltrate credentials",
                        fix: "Add --ignore-scripts, then explicitly rebuild trusted native deps: #{cmd[:name]} rebuild sharp esbuild"
                    )
                end
            end

            findings
        end

        private

        def workflow_has_secrets?(workflow)
            workflow.raw.match?(/\$\{\{\s*secrets\./)
        end
    end
end

module Rules
    class GitConfigGlobal < Base
        def name = "git-config-global"
        def description = "git config --global persists credentials beyond the repo clone"
        def severity = :medium

        def check(workflow)
            findings = []

            workflow.lines_of(/git config --global/).each do |line_num|
                line = workflow.line_content(line_num)
                next unless line&.match?(/insteadOf|url\.|credential/)

                findings << finding(workflow,
                    line: line_num,
                    code: line.strip,
                    message: "git config --global writes credentials to ~/.gitconfig — accessible to all subsequent git operations",
                    fix: "Use --local instead of --global to scope to the repo clone"
                )
            end

            findings
        end
    end
end

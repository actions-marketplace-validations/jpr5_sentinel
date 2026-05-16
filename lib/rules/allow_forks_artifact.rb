module Rules
    class AllowForksArtifact < Base
        def name = "allow-forks-artifact"
        def description = "Artifact download with allow_forks: true in privileged context"
        def severity = :medium

        def check(workflow)
            findings = []

            workflow.lines_of(/allow_forks:\s*true/).each do |line_num|
                findings << finding(workflow,
                    line: line_num,
                    code: workflow.line_content(line_num).strip,
                    message: "Downloading fork-produced artifacts in a privileged workflow_run context",
                    fix: "Ensure fork-produced artifact content is not executed or processed unsafely"
                )
            end

            findings
        end
    end
end

module Rules
    class UnscopedAppToken < Base
        def name = "unscoped-app-token"
        def description = "GitHub App token without scoped permissions"
        def severity = :high

        def check(workflow)
            findings = []

            workflow.jobs.each do |_job_id, job|
                workflow.steps(job).each do |step|
                    next unless step["uses"]&.include?("create-github-app-token")

                    with = step["with"] || {}
                    has_permissions = with.keys.any? { |k| k.start_with?("permission-") }

                    unless has_permissions
                        line = workflow.line_of(/create-github-app-token/)
                        findings << finding(workflow,
                            line: line || 0,
                            message: "App token inherits blanket installation permissions",
                            fix: "Add permission-<name>: write inputs to scope the token"
                        )
                    end
                end
            end

            findings
        end
    end
end

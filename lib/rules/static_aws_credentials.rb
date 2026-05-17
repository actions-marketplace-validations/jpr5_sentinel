module Rules
    class StaticAwsCredentials < Base
        def name = "static-aws-credentials"
        def description = "AWS credentials using static keys instead of OIDC"
        def severity = :medium

        def check(workflow)
            findings = []

            workflow.jobs.each do |_job_id, job|
                workflow.steps(job).each do |step|
                    next unless step["uses"]&.include?("configure-aws-credentials")

                    with = step["with"] || {}
                    has_static = with.key?("aws-access-key-id")
                    has_oidc = with.key?("role-to-assume")

                    if has_static && !has_oidc
                        line = workflow.line_of(/aws-access-key-id/)
                        findings << finding(workflow,
                            line: line || 0,
                            code: "aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}",
                            message: "Static AWS access keys — long-lived credentials that don't auto-expire",
                            fix: "Use OIDC federation: role-to-assume with id-token: write permission"
                        )
                    end
                end
            end

            findings
        end
    end
end

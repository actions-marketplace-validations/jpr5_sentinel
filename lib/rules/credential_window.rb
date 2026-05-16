module Rules
    class CredentialWindow < Base
        def name = "credential-window"
        def description = "Git credentials configured far before push step"
        def severity = :high

        MAX_STEPS_BETWEEN = 5

        def check(workflow)
            findings = []

            workflow.jobs.each do |_job_id, job|
                steps = workflow.steps(job)
                cred_step = nil
                push_step = nil

                steps.each_with_index do |step, i|
                    run = step["run"]&.to_s
                    if run&.match?(/git config.*insteadOf|git remote set-url/)
                        cred_step = i if cred_step.nil?
                    end
                    if run&.match?(/git push/)
                        push_step = i
                    end
                end

                next unless cred_step && push_step
                gap = push_step - cred_step

                if gap > MAX_STEPS_BETWEEN
                    line = workflow.line_of(/git config.*insteadOf|git remote set-url/)
                    findings << finding(workflow,
                        line: line || 0,
                        message: "Git credentials configured #{gap} steps before push — #{gap - 1} steps have access to the token",
                        fix: "Move credential configuration to immediately before the push step"
                    )
                end
            end

            findings
        end
    end
end

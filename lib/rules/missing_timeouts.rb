module Rules
    class MissingTimeouts < Base
        def name = "missing-timeouts"
        def description = "Job without timeout-minutes"
        def severity = :medium

        def check(workflow)
            findings = []

            workflow.jobs.each do |job_id, job|
                next if job.key?("timeout-minutes")

                line = workflow.line_of(/^\s+#{Regexp.escape(job_id)}:/)
                findings << finding(workflow,
                    line: line || 0,
                    code: "#{job_id}:",
                    message: "Job '#{job_id}' has no timeout-minutes — default is 360 minutes (6 hours)",
                    fix: "Add timeout-minutes: appropriate for the job type (5-30 min)"
                )
            end

            findings
        end
    end
end

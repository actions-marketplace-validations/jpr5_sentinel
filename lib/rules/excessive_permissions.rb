module Rules
    class ExcessivePermissions < Base
        def name = "excessive-permissions"
        def description = "Job has write permissions but no steps that appear to need them"
        def severity = :low

        # Actions that perform write operations
        WRITE_ACTIONS = [
            /peter-evans\/create-pull-request/,
            /stefanzweifel\/git-auto-commit-action/,
            /ad-m\/github-push-action/,
            /EndBug\/add-and-commit/,
        ].freeze

        # Run commands that require write access
        WRITE_COMMANDS = [
            /\bgit\s+push\b/,
            /\bgh\s+pr\s+create\b/,
            /\bgh\s+pr\s+merge\b/,
            /\bgh\s+pr\s+comment\b/,
            /\bgh\s+pr\s+review\b/,
            /\bgh\s+release\s+create\b/,
            /\bgh\s+api\b/,
        ].freeze

        def check(workflow)
            findings = []

            workflow.jobs.each do |job_id, job|
                job_perms = workflow.permissions(scope: :job, job: job)
                next unless job_perms.is_a?(Hash)
                next unless job_perms["contents"] == "write"

                steps = workflow.steps(job)
                next if has_write_operations?(steps)

                line = workflow.line_of(/^\s+#{Regexp.escape(job_id)}:/)
                findings << finding(workflow,
                    line: line || 0,
                    code: "#{job_id}: permissions: contents: write",
                    message: "This job has contents: write permission but no steps that appear to need it",
                    fix: "This job has write permissions but no steps that appear to need them. Consider restricting to contents: read."
                )
            end

            findings
        end

        private

        def has_write_operations?(steps)
            steps.any? do |step|
                # Check uses: for write actions
                if step["uses"]
                    return true if WRITE_ACTIONS.any? { |pattern| step["uses"].match?(pattern) }
                end

                # Check run: for write commands
                if step["run"]
                    return true if WRITE_COMMANDS.any? { |pattern| step["run"].match?(pattern) }
                end

                false
            end
        end
    end
end

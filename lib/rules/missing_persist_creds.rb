module Rules
  class MissingPersistCreds < Base
    def name = "missing-persist-credentials"
    def description = "actions/checkout without persist-credentials: false"
    def severity = :high

    def check(workflow)
      findings = []

      workflow.jobs.each do |_job_id, job|
        job_pushes = job_does_push?(job, workflow)

        workflow.steps(job).each do |step|
          next unless step["uses"]&.include?("checkout")

          with = step["with"] || {}
          persist = with["persist-credentials"]

          next if persist == false || persist == "false"
          next if job_pushes && persist == true

          line = find_checkout_line(workflow, step)
          findings << finding(workflow,
            line: line || 0,
            code: "uses: #{step['uses']}",
            message: "Checkout without persist-credentials: false — token persists in .git/config",
            fix: "Add persist-credentials: false to the with: block"
          )
        end
      end

      findings
    end

    private

    def job_does_push?(job, workflow)
      workflow.steps(job).any? { |s|
        run = s["run"]&.to_s
        run&.match?(/git push|gh pr create|peter-evans\/create-pull-request/) ||
          s["uses"]&.match?(/create-pull-request|yaml-update-action/)
      }
    end

    def find_checkout_line(workflow, step)
      uses = step["uses"]
      workflow.line_of(/uses:\s*#{Regexp.escape(uses)}/) if uses
    end
  end
end

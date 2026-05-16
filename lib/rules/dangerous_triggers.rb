module Rules
  class DangerousTriggers < Base
    def name = "dangerous-triggers"
    def description = "pull_request_target with fork code checkout"
    def severity = :critical

    def check(workflow)
      findings = []
      triggers = workflow.triggers

      has_prt = case triggers
                when Hash then triggers.key?("pull_request_target")
                when Array then triggers.include?("pull_request_target")
                when String then triggers == "pull_request_target"
                else false
                end

      return findings unless has_prt

      workflow.jobs.each do |_job_id, job|
        workflow.steps(job).each do |step|
          next unless step["uses"]&.include?("checkout")

          with = step["with"] || {}
          ref = with["ref"]&.to_s || ""

          if ref.match?(/\bgithub\.event\.pull_request\.head\b|\.head_ref\b|pull_request\.head\.sha/i) ||
             ref.match?(/\$\{\{\s*github\.head_ref\s*\}\}/)
            line = workflow.line_of(/ref:.*head/i) || workflow.line_of(/checkout/)
            findings << finding(workflow,
              line: line || 0,
              code: "ref: #{ref}",
              message: "pull_request_target + checkout of PR head — fork code runs with base repo secrets",
              fix: "Use pull_request trigger instead, or don't checkout PR head code"
            )
          end
        end
      end

      findings
    end
  end
end

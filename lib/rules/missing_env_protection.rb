module Rules
  class MissingEnvProtection < Base
    def name = "missing-env-protection"
    def description = "Publish/deploy job without GitHub Environment protection"
    def severity = :medium

    PUBLISH_INDICATORS = /npm publish|pnpm publish|twine upload|gem push|docker push|railway up|cdk deploy/
    OIDC_PUBLISH = /id-token:\s*write/

    def check(workflow)
      findings = []

      workflow.jobs.each do |job_id, job|
        next if job.key?("environment")

        steps = workflow.steps(job)
        has_publish = steps.any? { |s| s["run"]&.match?(PUBLISH_INDICATORS) }

        job_perms = workflow.permissions(scope: :job, job: job)
        has_oidc = job_perms&.to_s&.match?(OIDC_PUBLISH) ||
                   workflow.permissions(scope: :workflow)&.to_s&.match?(OIDC_PUBLISH)

        if has_publish || has_oidc
          line = workflow.line_of(/^\s+#{Regexp.escape(job_id)}:/)
          findings << finding(workflow,
            line: line || 0,
            code: "#{job_id}:",
            message: "Publish/deploy job without environment protection — no human gate before publication",
            fix: "Add environment: <name> with required reviewers"
          )
        end
      end

      findings
    end
  end
end

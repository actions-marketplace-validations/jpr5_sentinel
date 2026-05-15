module Rules
  class BuildPublishSameJob < Base
    def name = "build-publish-same-job"
    def description = "Build and publish in same job with publish secrets available during build"
    def severity = :high

    INSTALL_PATTERNS = /npm install|pnpm install|yarn install|pip install|bundle install/
    PUBLISH_PATTERNS = /npm publish|pnpm publish|npx pkg-pr-new|twine upload|gem push/
    PUBLISH_SECRETS = /NPM_TOKEN|PYPI_TOKEN|GEM_HOST_API_KEY|NUGET_API_KEY/

    def check(workflow)
      findings = []

      workflow.jobs.each do |job_id, job|
        steps = workflow.steps(job)
        has_install = steps.any? { |s| s["run"]&.match?(INSTALL_PATTERNS) }
        has_publish = steps.any? { |s| s["run"]&.match?(PUBLISH_PATTERNS) }

        next unless has_install && has_publish

        job_env = job["env"]&.to_s || ""
        step_envs = steps.map { |s| (s["env"] || {}).to_s }.join(" ")
        all_env = job_env + step_envs

        if all_env.match?(PUBLISH_SECRETS) || all_env.match?(/secrets\./)
          line = workflow.line_of(/#{job_id}:/)
          findings << finding(workflow,
            line: line || 0,
            code: "job: #{job_id}",
            message: "Build and publish in same job — a compromised dependency could exfiltrate publish credentials",
            fix: "Split into separate build (read-only) and publish (with secrets) jobs connected via artifacts"
          )
        end
      end

      findings
    end
  end
end

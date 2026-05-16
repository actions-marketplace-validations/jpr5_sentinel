module Rules
    class MissingEnvProtection < Base
        def name = "missing-env-protection"
        def description = "Publish/deploy job without GitHub Environment protection"
        def severity = :medium

        PUBLISH_INDICATORS = Regexp.union(
            # JavaScript / TypeScript
            /\bnpm\s+publish\b/,
            /\bpnpm\s+publish\b/,
            /\byarn\s+publish\b/,
            /\bnpx\s+pkg-pr-new\b/,
            # Python
            /\btwine\s+upload\b/,
            /\bpoetry\s+publish\b/,
            /\bflit\s+publish\b/,
            /\buv\s+publish\b/,
            # Ruby
            /\bgem\s+push\b/,
            /\brake\s+release\b/,
            # Rust
            /\bcargo\s+publish\b/,
            # Java / Kotlin
            /\bmvn\s+deploy\b/,
            /\bgradle\s+publish\b/,
            /\.\/gradlew\s+publish\b/,
            # .NET
            /\bdotnet\s+nuget\s+push\b/,
            /\bnuget\s+push\b/,
            # Docker
            /\bdocker\s+push\b/,
            /\bdocker\s+buildx\s+build\b.*--push/,
            # Infrastructure
            /\brailway\s+up\b/,
            /\bcdk\s+deploy\b/,
            /\bterraform\s+apply\b/,
            /\bpulumi\s+up\b/,
            /\bfly\s+deploy\b/,
            /\bheroku\s+container:push\b/,
            # Homebrew
            /\bbrew\s+bump-formula-pr\b/,
        )

        def check(workflow)
            findings = []

            workflow.jobs.each do |job_id, job|
                next if job.key?("environment")

                steps = workflow.steps(job)
                has_publish = steps.any? { |s| s["run"]&.match?(PUBLISH_INDICATORS) }

                has_oidc = oidc_id_token?(workflow.permissions(scope: :job, job: job)) ||
                                     oidc_id_token?(workflow.permissions(scope: :workflow))

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

        private

        def oidc_id_token?(perms)
            return false unless perms.is_a?(Hash)
            perms["id-token"] == "write"
        end
    end
end

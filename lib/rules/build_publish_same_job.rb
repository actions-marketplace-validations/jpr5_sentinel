module Rules
  class BuildPublishSameJob < Base
    def name = "build-publish-same-job"
    def description = "Build and publish in same job with publish secrets available during build"
    def severity = :high

    INSTALL_PATTERNS = Regexp.union(
      # JavaScript / TypeScript
      /\bnpm\s+(install|ci)\b/,
      /\bpnpm\s+install\b/,
      /\byarn\s+install\b/,
      /\byarn\b(?!\s+(publish|add|remove|run|build|test|lint))/,
      /\bbun\s+install\b/,
      # Python
      /\bpip3?\s+install\b/,
      /\buv\s+(pip\s+install|sync)\b/,
      /\bpoetry\s+install\b/,
      /\bpipenv\s+install\b/,
      /\bconda\s+install\b/,
      # Ruby
      /\bbundle\s+install\b/,
      /\bbundle\b(?!\s+(exec|push|open|show|update|outdated|gem))/,
      /\bgem\s+install\b/,
      # Go
      /\bgo\s+mod\s+download\b/,
      /\bgo\s+get\b/,
      /\bgo\s+install\b/,
      # Rust
      /\bcargo\s+(build|fetch)\b/,
      # Java / Kotlin
      /\bmvn\s+(install|package)\b/,
      /\bgradle\s+build\b/,
      /\.\/gradlew\s+build\b/,
      # .NET
      /\bdotnet\s+restore\b/,
      /\bnuget\s+restore\b/,
      # PHP
      /\bcomposer\s+(install|update)\b/,
      # Elixir
      /\bmix\s+deps\.get\b/,
      # Swift
      /\bswift\s+package\s+resolve\b/,
    )

    PUBLISH_PATTERNS = Regexp.union(
      # JavaScript / TypeScript
      /\bnpm\s+publish\b/,
      /\bpnpm\s+publish\b/,
      /\bnpx\s+pkg-pr-new\b/,
      /\byarn\s+publish\b/,
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
      # Homebrew
      /\bbrew\s+tap\b/,
      /\bbrew\s+bump-formula-pr\b/,
    )

    PUBLISH_SECRETS = Regexp.union(
      # JavaScript
      /\bNPM_TOKEN\b/,
      /\bNODE_AUTH_TOKEN\b/,
      /\bNPM_AUTH_TOKEN\b/,
      # Python
      /\bPYPI_TOKEN\b/,
      /\bPYPI_API_TOKEN\b/,
      /\bTWINE_PASSWORD\b/,
      /\bPOETRY_PYPI_TOKEN_PYPI\b/,
      # Ruby
      /\bGEM_HOST_API_KEY\b/,
      /\bRUBYGEMS_API_KEY\b/,
      /\bRUBYGEMS_AUTH_TOKEN\b/,
      # Rust
      /\bCARGO_REGISTRY_TOKEN\b/,
      /\bCRATES_IO_TOKEN\b/,
      # Java / Gradle
      /\bMAVEN_PASSWORD\b/,
      /\bMAVEN_GPG_PASSPHRASE\b/,
      /\bGRADLE_PUBLISH_KEY\b/,
      /\bOSSRH_PASSWORD\b/,
      /\bSONATYPE_PASSWORD\b/,
      # .NET
      /\bNUGET_API_KEY\b/,
      /\bNUGET_AUTH_TOKEN\b/,
      # Docker
      /\bDOCKER_PASSWORD\b/,
      /\bDOCKER_TOKEN\b/,
      /\bDOCKERHUB_TOKEN\b/,
      # General
      /\bREGISTRY_TOKEN\b/,
      /\bPUBLISH_TOKEN\b/,
    )

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

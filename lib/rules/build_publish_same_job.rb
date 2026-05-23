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

        # Match --ignore-scripts or --no-scripts as standalone flags or with =true.
        # Reject =false or other =value suffixes (which disable the mitigation).
        IGNORE_SCRIPTS_PATTERN = /(?:^|\s)(?:--ignore-scripts|--no-scripts)(?:=true)?(?=\s|$|[;&|\\])/

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
                install_steps = steps.select { |s| s["run"]&.match?(INSTALL_PATTERNS) }
                has_publish = steps.any? { |s| s["run"]&.match?(PUBLISH_PATTERNS) }

                next unless install_steps.any? && has_publish

                job_env = job["env"]&.to_s || ""
                step_envs = steps.map { |s| (s["env"] || {}).to_s }.join(" ")
                all_env = job_env + step_envs

                next unless all_env.match?(PUBLISH_SECRETS) || all_env.match?(/secrets\./)

                # Check if all install commands across all steps use --ignore-scripts.
                # Each step's run block may contain multiple commands; we check per
                # install command, not per run block.
                all_mitigated = install_steps.all? { |s| step_installs_mitigated?(s["run"]) }
                next if all_mitigated

                line = workflow.line_of(/#{job_id}:/)
                findings << finding(workflow,
                    line: line || 0,
                    code: "job: #{job_id}",
                    message: "Build and publish in same job — a compromised dependency could exfiltrate publish credentials",
                    fix: "Split into separate build (read-only) and publish (with secrets) jobs connected via artifacts"
                )
            end

            findings
        end

        private

        # Determine if every install command within a run block has --ignore-scripts.
        #
        # 1. Collapse shell line continuations (backslash-newline) into logical lines.
        # 2. Split on newlines to get individual logical commands.
        # 3. Strip trailing shell comments (unquoted #...) from each line before
        #    pattern matching so that `npm install # --ignore-scripts` does not
        #    falsely count as mitigated.
        # 4. For each logical line, check if it contains an install command.
        # 5. For each install command, verify --ignore-scripts is on that same line.
        #
        # Returns true only if EVERY install command in the block is mitigated.
        def step_installs_mitigated?(run_str)
            return true if run_str.nil?

            # Collapse backslash-newline continuations into single logical lines
            collapsed = run_str.gsub(/\\\s*\n\s*/, " ")

            # Split into individual logical lines
            lines = collapsed.split("\n")

            install_lines = lines.select { |line|
                stripped = line.strip
                next false if stripped.start_with?("#")
                strip_shell_comment(stripped).match?(INSTALL_PATTERNS)
            }

            # If no install lines found, the step is trivially mitigated
            return true if install_lines.empty?

            # Every install line must have --ignore-scripts on the code portion
            install_lines.all? { |line| strip_shell_comment(line).match?(IGNORE_SCRIPTS_PATTERN) }
        end

        # Strip trailing shell comments from a line, respecting single and double
        # quotes. Returns the code portion before any unquoted `#`.
        def strip_shell_comment(line)
            in_single = false
            in_double = false
            i = 0

            while i < line.length
                ch = line[i]

                # Backslash escapes the next character in unquoted and double-quoted
                # context, but NOT inside single quotes (POSIX: backslash is literal
                # within single-quoted strings).
                if ch == '\\' && !in_single
                    i += 2
                    next
                end

                case ch
                when "'" then in_single = !in_single unless in_double
                when '"' then in_double = !in_double unless in_single
                when '#'
                    unless in_single || in_double
                        # Only treat as comment when at start of line or preceded by whitespace
                        if i == 0 || line[i - 1] =~ /\s/
                            return line[0...i]
                        end
                    end
                end

                i += 1
            end

            line
        end
    end
end

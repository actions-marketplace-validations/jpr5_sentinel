require_relative "../finding"

module Platforms
    module SharedPatterns
        SECRET_PATTERNS = {
            "AWS access key" => /AKIA[0-9A-Z]{16}/,
            "GitHub personal access token" => /ghp_[A-Za-z0-9]{36}/,
            "GitHub fine-grained PAT" => /github_pat_[A-Za-z0-9_]{82}/,
            "GitHub OAuth token" => /gho_[A-Za-z0-9]{36}/,
            "GitHub server token" => /ghs_[A-Za-z0-9]{36}/,
            "Private key" => /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
            "Slack webhook" => /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
            "Generic API key" => /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/i,
        }.freeze

        PASSWORD_PATTERN = /password:\s*[^\s${\#]+/i
        SAFE_VALUE_PATTERN = /\$\{\{.*\}\}|\$[A-Z_]+|\$\{[A-Z_]+\}/

        def scan_for_hardcoded_secrets(lines, filename:, platform_fix:)
            findings = []

            lines.each_with_index do |line, idx|
                line_num = idx + 1
                stripped = line.strip

                next if stripped.start_with?("#")

                SECRET_PATTERNS.each do |label, pattern|
                    if line.match?(pattern)
                        findings << Finding.new(
                            rule: "hardcoded-secrets",
                            severity: :critical,
                            file: filename,
                            line: line_num,
                            code: stripped,
                            message: "#{label} found hardcoded in CI config",
                            fix: platform_fix
                        )
                    end
                end

                if line.match?(PASSWORD_PATTERN)
                    value = line[/password:\s*(.+)/i, 1]&.strip
                    if value && !value.match?(SAFE_VALUE_PATTERN) && !value.start_with?("#")
                        findings << Finding.new(
                            rule: "hardcoded-secrets",
                            severity: :critical,
                            file: filename,
                            line: line_num,
                            code: stripped,
                            message: "Hardcoded password found in CI config",
                            fix: platform_fix
                        )
                    end
                end
            end

            findings
        end

        def scan_for_missing_timeout(jobs_hash, lines, filename:, timeout_key:, platform_fix:)
            findings = []

            jobs_hash.each do |job_id, job|
                next unless job.is_a?(Hash)
                next if job.key?(timeout_key)

                line = find_line(lines, /^\s+#{Regexp.escape(job_id.to_s)}:/)
                findings << Finding.new(
                    rule: "missing-timeout",
                    severity: :medium,
                    file: filename,
                    line: line || 0,
                    code: "#{job_id}:",
                    message: "Job '#{job_id}' has no #{timeout_key}",
                    fix: platform_fix
                )
            end

            findings
        end

        def find_line(lines, pattern)
            lines.each_with_index do |line, i|
                return i + 1 if line.match?(pattern)
            end
            nil
        end

        def find_all_lines(lines, pattern)
            results = []
            lines.each_with_index do |line, i|
                results << (i + 1) if line.match?(pattern)
            end
            results
        end

        def line_content(lines, num)
            lines[num - 1]&.rstrip
        end
    end
end

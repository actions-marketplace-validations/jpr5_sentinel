module Rules
    class HardcodedSecrets < Base
        def name = "hardcoded-secrets"
        def description = "Hardcoded secret, token, or key in workflow"
        def severity = :critical

        PATTERNS = {
            "AWS access key" => /AKIA[0-9A-Z]{16}/,
            "GitHub personal access token" => /ghp_[A-Za-z0-9]{36}/,
            "GitHub fine-grained PAT" => /github_pat_[A-Za-z0-9_]{82}/,
            "GitHub OAuth token" => /gho_[A-Za-z0-9]{36}/,
            "GitHub server token" => /ghs_[A-Za-z0-9]{36}/,
            "Private key" => /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
            "Slack webhook" => /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
            "Generic API key" => /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9]{30,}['"]/i,
        }.freeze

        PASSWORD_PATTERN = /password:\s*[^\s${\#]+/i
        SAFE_VALUE_PATTERN = /\$\{\{.*\}\}|\$[A-Z_]+/
        SAFE_PASSWORDS = %w[postgres password test example changeme admin root dummy placeholder].freeze

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, idx|
                line_num = idx + 1
                stripped = line.strip

                # Skip comment lines
                next if stripped.start_with?("#")

                PATTERNS.each do |label, pattern|
                    if line.match?(pattern)
                        findings << finding(workflow,
                            line: line_num,
                            code: stripped,
                            message: "#{label} found hardcoded in workflow",
                            fix: "Move to GitHub Actions secrets: ${{ secrets.SECRET_NAME }}"
                        )
                    end
                end

                # Check for hardcoded passwords (skip safe references and common test values)
                if line.match?(PASSWORD_PATTERN)
                    # Extract the value after password:
                    value = line[/password:\s*(.+)/i, 1]&.strip
                    if value && !value.match?(SAFE_VALUE_PATTERN) && !value.start_with?("#")
                        next if SAFE_PASSWORDS.include?(value.strip.downcase)
                        findings << finding(workflow,
                            line: line_num,
                            code: stripped,
                            message: "Hardcoded password found in workflow",
                            fix: "Move to GitHub Actions secrets: ${{ secrets.SECRET_NAME }}"
                        )
                    end
                end
            end

            findings
        end
    end
end

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
        SAFE_VALUE_PATTERN = /\$\{\{.*\}\}|\$[A-Z_]+|\A[A-Z][A-Z0-9_]+\z/
        SAFE_PASSWORDS = %w[postgres password test example changeme admin root dummy placeholder true false].freeze

        # Actions whose `with:` slots accept env-var *names* (not values).
        # When the value looks like an UPPER_SNAKE_CASE identifier it is an
        # env-var name reference, not a hardcoded credential.
        ENV_NAME_SLOTS = {
            /actions\/setup-java/ => %w[server-username server-password gpg-passphrase gpg-private-key keystore-password],
        }.freeze

        ENV_VAR_NAME_PATTERN = /\A[A-Z][A-Z0-9_]*\z/

        def check(workflow)
            findings = []
            allowlisted_lines = build_env_name_slot_lines(workflow)

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
                        next if allowlisted_lines.include?(line_num)
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

        private

        # Build a list of line numbers where a known action's `with:` slot
        # contains an env-var name (UPPER_SNAKE_CASE) rather than a credential.
        def build_env_name_slot_lines(workflow)
            lines = []
            workflow.jobs.each do |_job_id, job_hash|
                workflow.steps(job_hash).each do |step|
                    next unless step["uses"]
                    ENV_NAME_SLOTS.each do |action_pattern, slot_names|
                        next unless step["uses"].match?(action_pattern)
                        with_block = step["with"] || {}
                        slot_names.each do |slot|
                            next unless with_block[slot]
                            value = with_block[slot].to_s.strip
                            next unless value.match?(ENV_VAR_NAME_PATTERN)
                            workflow.raw_lines.each_with_index do |raw_line, idx|
                                if raw_line.match?(/\b#{Regexp.escape(slot)}:\s*#{Regexp.escape(value)}\b/)
                                    lines << (idx + 1)
                                end
                            end
                        end
                    end
                end
            end
            lines
        end
    end
end

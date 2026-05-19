require "yaml"
require_relative "shared_patterns"

module Platforms
    class GitLab
        include SharedPatterns

        def initialize(content, filename: ".gitlab-ci.yml")
            @content = content
            @filename = filename
            @data = YAML.safe_load(content, aliases: true) || {}
            @lines = content.lines
        rescue YAML::SyntaxError
            @data = {}
            @lines = []
        end

        def scan
            findings = []
            findings.concat(check_secrets_in_variables)
            findings.concat(check_unprotected_branches)
            findings.concat(check_allow_failure_security)
            findings.concat(check_privileged_docker)
            findings.concat(check_script_injection)
            findings.concat(check_include_remote)
            findings.concat(check_missing_timeout)
            findings.sort
        end

        private

        def check_secrets_in_variables
            findings = []

            if @data["variables"].is_a?(Hash)
                @data["variables"].each do |key, value|
                    next unless value.is_a?(String)
                    findings.concat(check_variable_value(key, value))
                end
            end

            each_job do |job_id, job|
                next unless job["variables"].is_a?(Hash)
                job["variables"].each do |key, value|
                    next unless value.is_a?(String)
                    findings.concat(check_variable_value(key, value, job_id: job_id))
                end
            end

            findings.concat(scan_for_hardcoded_secrets(@lines,
                filename: @filename,
                platform_fix: "Move to GitLab CI/CD Variables (Settings > CI/CD > Variables)"
            ))

            findings.uniq { |f| [f.line, f.rule, f.message] }
        end

        def check_variable_value(key, value, job_id: nil)
            findings = []
            SECRET_PATTERNS.each do |label, pattern|
                if value.match?(pattern)
                    context = job_id ? "job '#{job_id}'" : "top-level"
                    line = find_line(@lines, /#{Regexp.escape(key)}:/)
                    findings << Finding.new(
                        rule: "hardcoded-secrets",
                        severity: :critical,
                        file: @filename,
                        line: line || 0,
                        code: "#{key}: #{value[0..20]}...",
                        message: "#{label} hardcoded in #{context} variables",
                        fix: "Move to GitLab CI/CD Variables (Settings > CI/CD > Variables)"
                    )
                end
            end
            findings
        end

        def check_unprotected_branches
            findings = []

            each_job do |job_id, job|
                next if job["only"] || job["except"] || job["rules"]

                scripts = extract_scripts(job)
                next if scripts.empty?
                next unless scripts.any? { |s| s.match?(/deploy|publish|release|push/i) }

                line = find_line(@lines, /^\s+#{Regexp.escape(job_id)}:/)
                findings << Finding.new(
                    rule: "unprotected-branches",
                    severity: :medium,
                    file: @filename,
                    line: line || 0,
                    code: "#{job_id}:",
                    message: "Job '#{job_id}' performs deploy/publish with no branch restrictions",
                    fix: "Add only:/except: or rules: to restrict to protected branches"
                )
            end

            findings
        end

        def check_allow_failure_security
            findings = []
            security_keywords = /\b(sast|dast|secret.?detect|security|vulnerability|scan|audit|trivy|snyk|semgrep)\b/i

            each_job do |job_id, job|
                next unless job["allow_failure"] == true

                is_security = job_id.match?(security_keywords)
                scripts = extract_scripts(job)
                is_security ||= scripts.any? { |s| s.match?(security_keywords) }
                is_security ||= (job["image"].is_a?(String) && job["image"].match?(security_keywords))
                next unless is_security

                line = find_line(@lines, /^\s+#{Regexp.escape(job_id)}:/)
                findings << Finding.new(
                    rule: "allow-failure-security",
                    severity: :high,
                    file: @filename,
                    line: line || 0,
                    code: "allow_failure: true",
                    message: "Security job '#{job_id}' has allow_failure: true — failures will be silently ignored",
                    fix: "Remove allow_failure or set allow_failure: false for security-critical jobs"
                )
            end

            findings
        end

        def check_privileged_docker
            findings = []

            each_job do |job_id, job|
                variables = job["variables"] || {}
                if variables["DOCKER_HOST"] || job_id.match?(/dind|docker/i)
                    image = job["image"]
                    if image.is_a?(String) && image.match?(/docker.*dind/)
                        line = find_line(@lines, /#{Regexp.escape(image)}/)
                        findings << Finding.new(
                            rule: "privileged-docker",
                            severity: :high,
                            file: @filename,
                            line: line || 0,
                            code: "image: #{image}",
                            message: "Job '#{job_id}' uses Docker-in-Docker image — likely requires privileged mode",
                            fix: "Use kaniko or buildah for unprivileged container builds, or restrict to protected runners"
                        )
                    end
                end

                tags = job["tags"]
                if tags.is_a?(Array) && tags.any? { |t| t.to_s.match?(/privileged/) }
                    line = find_line(@lines, /privileged/)
                    findings << Finding.new(
                        rule: "privileged-docker",
                        severity: :high,
                        file: @filename,
                        line: line || 0,
                        code: "tags: [#{tags.join(', ')}]",
                        message: "Job '#{job_id}' requests privileged runner via tags",
                        fix: "Use kaniko or buildah for unprivileged container builds, or restrict to protected runners"
                    )
                end
            end

            find_all_lines(@lines, /^\s+privileged:\s*true/).each do |line_num|
                findings << Finding.new(
                    rule: "privileged-docker",
                    severity: :high,
                    file: @filename,
                    line: line_num,
                    code: line_content(@lines, line_num)&.strip,
                    message: "Privileged mode enabled — container has full host access",
                    fix: "Use kaniko or buildah for unprivileged container builds, or restrict to protected runners"
                )
            end

            findings.uniq { |f| [f.line, f.rule] }
        end

        DANGEROUS_CI_VARS = %w[
            CI_MERGE_REQUEST_TITLE
            CI_MERGE_REQUEST_DESCRIPTION
            CI_COMMIT_MESSAGE
            CI_COMMIT_TAG_MESSAGE
            CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
            CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME
        ].freeze

        def check_script_injection
            findings = []

            each_job do |job_id, job|
                scripts = extract_scripts(job)
                scripts.each do |script_line|
                    DANGEROUS_CI_VARS.each do |var|
                        if script_line.include?("$#{var}") || script_line.include?("${#{var}}")
                            pattern = /#{Regexp.escape(var)}/
                            lines = find_all_lines(@lines, pattern)
                            lines.each do |line_num|
                                findings << Finding.new(
                                    rule: "script-injection",
                                    severity: :critical,
                                    file: @filename,
                                    line: line_num,
                                    code: line_content(@lines, line_num)&.strip,
                                    message: "CI variable $#{var} in script is attacker-controllable — injection risk",
                                    fix: "Assign to a variable first and validate/sanitize before use in shell commands"
                                )
                            end
                        end
                    end
                end
            end

            findings.uniq { |f| [f.line, f.rule, f.message] }
        end

        def check_include_remote
            findings = []
            includes = @data["include"]
            return findings unless includes

            includes = [includes] unless includes.is_a?(Array)

            includes.each do |inc|
                case inc
                when Hash
                    if inc["remote"]
                        url = inc["remote"]
                        unless url.match?(/[?&]ref=[0-9a-f]{40}/) || url.match?(/\/raw\/[0-9a-f]{40}\//)
                            line = find_line(@lines, /#{Regexp.escape(url[0..40])}/)
                            findings << Finding.new(
                                rule: "unpinned-include",
                                severity: :critical,
                                file: @filename,
                                line: line || 0,
                                code: "remote: #{url}",
                                message: "Remote include '#{url}' is not SHA-pinned — content can change without notice",
                                fix: "Pin to a specific commit SHA in the URL or use project includes with ref:"
                            )
                        end
                    end

                    if inc["project"] && !inc["ref"]
                        project = inc["project"]
                        line = find_line(@lines, /project:\s*['"]?#{Regexp.escape(project)}/)
                        findings << Finding.new(
                            rule: "unpinned-include",
                            severity: :high,
                            file: @filename,
                            line: line || 0,
                            code: "project: #{project}",
                            message: "Project include '#{project}' has no ref: — defaults to HEAD which can change",
                            fix: "Add ref: with a specific tag or SHA to pin the included config"
                        )
                    end
                when String
                    if inc.match?(/^https?:\/\//)
                        unless inc.match?(/[?&]ref=[0-9a-f]{40}/) || inc.match?(/\/raw\/[0-9a-f]{40}\//)
                            line = find_line(@lines, /#{Regexp.escape(inc[0..40])}/)
                            findings << Finding.new(
                                rule: "unpinned-include",
                                severity: :critical,
                                file: @filename,
                                line: line || 0,
                                code: inc,
                                message: "Remote include '#{inc}' is not SHA-pinned",
                                fix: "Pin to a specific commit SHA in the URL"
                            )
                        end
                    end
                end
            end

            findings
        end

        def check_missing_timeout
            jobs = {}
            each_job { |id, job| jobs[id] = job }

            scan_for_missing_timeout(jobs, @lines,
                filename: @filename,
                timeout_key: "timeout",
                platform_fix: "Add timeout: (e.g., '30 minutes') to limit job execution time"
            )
        end

        RESERVED_KEYS = %w[
            image services stages variables before_script after_script cache
            include default workflow pages
        ].freeze

        def each_job
            @data.each do |key, value|
                next if RESERVED_KEYS.include?(key)
                next unless value.is_a?(Hash)
                next if key == "stages"
                yield key, value
            end
        end

        def extract_scripts(job)
            scripts = []
            %w[script before_script after_script].each do |key|
                val = job[key]
                case val
                when Array then scripts.concat(val.map(&:to_s))
                when String then scripts << val
                end
            end
            scripts
        end
    end
end

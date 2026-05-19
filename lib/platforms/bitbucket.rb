require "yaml"
require_relative "shared_patterns"

module Platforms
    class Bitbucket
        include SharedPatterns

        def initialize(content, filename: "bitbucket-pipelines.yml")
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
            findings.concat(check_script_injection)
            findings.concat(check_unpinned_pipes)
            findings.concat(check_max_time)
            findings.concat(check_hardcoded_secrets)
            findings.sort
        end

        private

        DANGEROUS_BB_VARS = %w[
            BITBUCKET_PR_TITLE
            BITBUCKET_PR_DESCRIPTION
            BITBUCKET_BRANCH
            BITBUCKET_TAG
            BITBUCKET_BOOKMARK
        ].freeze

        def check_script_injection
            findings = []

            each_step do |step, context|
                scripts = extract_scripts(step)
                scripts.each do |script_line|
                    DANGEROUS_BB_VARS.each do |var|
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
                                    message: "Bitbucket variable $#{var} in script is attacker-controllable — injection risk",
                                    fix: "Validate/sanitize the variable before use in shell commands"
                                )
                            end
                        end
                    end
                end
            end

            findings.uniq { |f| [f.line, f.rule, f.message] }
        end

        def check_unpinned_pipes
            findings = []

            each_step do |step, _context|
                pipe = step["pipe"]
                next unless pipe.is_a?(String)

                next if pipe.match?(/@[0-9a-f]{40}\b/)
                next if pipe.match?(/@sha256:[0-9a-f]{64}/)
                next if pipe.match?(/docker:\/\/.*@sha256:/)

                line = find_line(@lines, /pipe:\s*['"]?#{Regexp.escape(pipe)}/)
                line ||= find_line(@lines, /pipe:.*#{Regexp.escape(pipe.split(':').first)}/)

                findings << Finding.new(
                    rule: "unpinned-pipe",
                    severity: :high,
                    file: @filename,
                    line: line || 0,
                    code: "pipe: #{pipe}",
                    message: "Pipe '#{pipe}' is not SHA-pinned — tag references are mutable",
                    fix: "Pin to a specific commit SHA or docker digest"
                )
            end

            findings
        end

        def check_max_time
            findings = []

            global_max_time = @data.dig("options", "max-time")

            each_step do |step, context|
                next if step.key?("max-time")
                next if global_max_time

                step_name = step["name"]
                line = if step_name
                    find_line(@lines, /name:\s*['"]?#{Regexp.escape(step_name)}/)
                else
                    scripts = extract_scripts(step)
                    scripts.first ? find_line(@lines, /#{Regexp.escape(scripts.first[0..30])}/) : nil
                end

                findings << Finding.new(
                    rule: "missing-max-time",
                    severity: :medium,
                    file: @filename,
                    line: line || 0,
                    code: step_name ? "name: #{step_name}" : "step",
                    message: "Step#{step_name ? " '#{step_name}'" : ''} has no max-time — default is 120 minutes#{context ? " (in #{context})" : ''}",
                    fix: "Add max-time: (in minutes) to limit step execution time"
                )
            end

            findings
        end

        def check_hardcoded_secrets
            scan_for_hardcoded_secrets(@lines,
                filename: @filename,
                platform_fix: "Move to Bitbucket Pipelines repository variables (Repository settings > Pipelines > Variables)"
            )
        end

        def each_step(&block)
            walk_pipeline_steps(@data.dig("pipelines", "default"), "default", &block)

            branches = @data.dig("pipelines", "branches")
            if branches.is_a?(Hash)
                branches.each do |branch, steps|
                    walk_pipeline_steps(steps, "branches/#{branch}", &block)
                end
            end

            tags = @data.dig("pipelines", "tags")
            if tags.is_a?(Hash)
                tags.each do |tag, steps|
                    walk_pipeline_steps(steps, "tags/#{tag}", &block)
                end
            end

            prs = @data.dig("pipelines", "pull-requests")
            if prs.is_a?(Hash)
                prs.each do |pattern, steps|
                    walk_pipeline_steps(steps, "pull-requests/#{pattern}", &block)
                end
            end

            custom = @data.dig("pipelines", "custom")
            if custom.is_a?(Hash)
                custom.each do |name, config|
                    steps = config.is_a?(Array) ? config : config&.dig("steps") || config
                    walk_pipeline_steps(steps, "custom/#{name}", &block) if steps.is_a?(Array)
                end
            end
        end

        def walk_pipeline_steps(steps, context, &block)
            return unless steps.is_a?(Array)

            steps.each do |entry|
                if entry.is_a?(Hash)
                    if entry["step"]
                        yield entry["step"], context
                    elsif entry["parallel"]
                        parallel = entry["parallel"]
                        parallel = parallel["steps"] if parallel.is_a?(Hash) && parallel["steps"]
                        if parallel.is_a?(Array)
                            parallel.each do |p|
                                yield p["step"], context if p.is_a?(Hash) && p["step"]
                            end
                        end
                    end
                end
            end
        end

        def extract_scripts(step)
            scripts = []
            val = step["script"]
            case val
            when Array then scripts.concat(val.map(&:to_s))
            when String then scripts << val
            end

            val = step["after-script"]
            case val
            when Array then scripts.concat(val.map(&:to_s))
            when String then scripts << val
            end

            scripts
        end
    end
end

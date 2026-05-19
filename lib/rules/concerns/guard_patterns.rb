module Rules
    module GuardPatterns
        SAFE_TRIGGERS = %w[
            workflow_dispatch schedule push workflow_call release
            deployment deployment_status create delete
            page_build watch fork star gollum
        ].freeze

        JOB_PROPERTIES = %w[
            steps runs-on env strategy permissions outputs concurrency
            services needs container timeout-minutes if name defaults
        ].freeze

        DANGEROUS_CONTEXTS = %w[
            github.event.pull_request.title
            github.event.pull_request.body
            github.event.pull_request.head.ref
            github.event.pull_request.head.label
            github.event.issue.title
            github.event.issue.body
            github.event.comment.body
            github.event.review.body
            github.event.discussion.title
            github.event.discussion.body
            github.event.workflow_run.head_branch
            github.head_ref
        ].freeze

        def safe_trigger_only?(workflow)
            trigger_names = case workflow.triggers
            when Hash then workflow.triggers.keys.map(&:to_s)
            when Array then workflow.triggers.map(&:to_s)
            when String then [workflow.triggers]
            else []
            end

            trigger_names.any? && trigger_names.all? { |t| SAFE_TRIGGERS.include?(t) }
        end

        def guarded_by_safe_event?(workflow, line_num)
            guarded_by_step_if?(workflow, line_num) || guarded_by_job_if?(workflow, line_num)
        end

        def strip_inline_comment(line)
            in_single_quote = false
            in_double_quote = false

            i = 0
            while i < line.length
                char = line[i]

                if char == "'" && !in_double_quote
                    in_single_quote = !in_single_quote
                elsif char == '"' && !in_single_quote
                    in_double_quote = !in_double_quote
                elsif char == '#' && !in_single_quote && !in_double_quote
                    # Only strip if preceded by whitespace (or at start of line content)
                    if i == 0 || line[i - 1] =~ /\s/
                        return line[0...i].rstrip
                    end
                end

                i += 1
            end

            line
        end

        private

        # Walk upward from line_num looking for a step-level `if:` guard.
        # Stop at step boundaries: a line matching `^\s*-\s+` at the same or
        # lower indent as the step's dash signals a different step.
        def guarded_by_step_if?(workflow, line_num)
            (line_num - 2).downto([line_num - 30, 0].max) do |i|
                content = workflow.raw_lines[i]
                next unless content

                # Found step-level `if:` before hitting a boundary
                if content.match?(/^\s+if:\s*/)
                    condition = content[/if:\s*(.+)/, 1]&.strip
                    return safe_guard_condition?(condition) if condition
                end

                # Step boundary: a line starting with `- ` at step indent
                if content.match?(/^\s+-\s+\S/)
                    # Check if the step boundary itself is `- if:` (guard on dash line)
                    if content.match?(/^\s+-\s+if:\s*/)
                        condition = content[/if:\s*(.+)/, 1]&.strip
                        return safe_guard_condition?(condition) if condition
                    end
                    break
                end

                # Job-level key (no dash prefix, at job indent) means we've left the step
                if content.match?(/^\s+\w[\w-]*:/) && !content.match?(/^\s+-/)
                    indent = content[/^\s*/].length
                    # If this is shallow (job key level), stop
                    break if indent <= 6
                end
            end

            false
        end

        # Walk upward from line_num looking for a job-level `if:` guard.
        # Stop at `jobs:` key or when crossing into a different job.
        def guarded_by_job_if?(workflow, line_num)
            # Track job key boundaries: the first job key we encounter going
            # upward is the enclosing job; the second means we've left it.
            job_keys_seen = 0
            enclosing_job_line = nil

            (line_num - 2).downto(0) do |i|
                content = workflow.raw_lines[i]
                next unless content

                # `jobs:` means we've gone too far without finding a job-level if:
                return false if content.match?(/^jobs:\s*$/)

                # Detect job key lines (e.g. "  build:" at job-key indent)
                if content.match?(/^\s+(\w[\w-]*):\s*$/)
                    key_name = content[/^\s+(\w[\w-]*):\s*$/, 1]
                    key_indent = content[/^\s*/].length
                    # Job keys are typically at indent 2 (under `jobs:`);
                    # skip known job properties (steps:, permissions:, etc.)
                    if key_indent <= 4 && !JOB_PROPERTIES.include?(key_name)
                        job_keys_seen += 1
                        enclosing_job_line = i if job_keys_seen == 1
                        # Second job key means we've crossed into a different job
                        return false if job_keys_seen > 1
                    end
                end

                # Job-level `if:` — directly under a job key, typically at indent 4 or 6
                if content.match?(/^\s+if:\s*/)
                    # Check if this is job-level (not step-level) by verifying indent
                    if_indent = content[/^\s*/].length

                    # Look further up to see if there's a job key at indent - 2
                    (i - 1).downto([i - 15, 0].max) do |j|
                        above = workflow.raw_lines[j]
                        next unless above

                        if above.match?(/^\s+\w[\w-]*:\s*$/)
                            above_indent = above[/^\s*/].length
                            # The job key above must be our enclosing job, not a
                            # different one. If we already found the enclosing job
                            # key, verify this `if:` belongs to it.
                            if if_indent == above_indent + 2 &&
                               (enclosing_job_line.nil? || j == enclosing_job_line)
                                condition = content[/if:\s*(.+)/, 1]&.strip
                                return safe_guard_condition?(condition) if condition
                            end
                            break
                        end
                    end
                end

                # `steps:` key means we've passed from steps into job-level territory
                next if content.match?(/^\s+steps:\s*$/)
            end

            false
        end

        # Check if a simple `if:` condition clearly excludes attacker-controlled triggers.
        # Only matches simple single-clause guards, not complex boolean expressions.
        def safe_guard_condition?(condition)
            # Strip ${{ }} wrapper if present
            condition = condition.gsub(/\$\{\{\s*/, '').gsub(/\s*\}\}/, '').strip

            # Reject complex expressions
            return false if condition.match?(/(\|\||&&|always\s*\(|failure\s*\(|cancelled\s*\()/)

            # Pattern: github.event_name == 'push' (or any SAFE_TRIGGER)
            if (m = condition.match(/\Agithub\.event_name\s*==\s*['"](\w+)['"]\z/))
                return SAFE_TRIGGERS.include?(m[1])
            end

            false
        end
    end
end

module Rules
    class SelfHostedRunnerFork < Base
        def name = "self-hosted-runner-fork"
        def description = "Self-hosted runner exposed to fork PRs"
        def severity = :critical

        FORK_TRIGGERS = %w[pull_request pull_request_target].freeze

        def check(workflow)
            findings = []
            triggers = workflow.triggers

            fork_trigger = detect_fork_trigger(triggers)
            return findings unless fork_trigger

            # Skip if the trigger is gated by label-based types
            if gated_by_label?(triggers, fork_trigger)
                return findings
            end

            runs_on_lines = workflow.lines_of(/runs-on:/)
            runs_on_idx = 0

            workflow.jobs.each do |job_id, job|
                runs_on = job["runs-on"]
                next unless runs_on

                runs_on_str = runs_on.is_a?(Array) ? runs_on.join(", ") : runs_on.to_s

                # Advance through runs-on lines for each job regardless of self-hosted
                line = runs_on_lines[runs_on_idx]
                runs_on_idx += 1

                next unless runs_on_str.include?("self-hosted")

                findings << finding(workflow,
                    line: line || 0,
                    code: "runs-on: #{runs_on_str}",
                    message: "Self-hosted runner with '#{fork_trigger}' trigger — fork PRs can run arbitrary code on your infrastructure",
                    fix: "Use GitHub-hosted runners for fork PR workflows, or gate with a label-based trigger"
                )
            end

            findings
        end

        private

        def detect_fork_trigger(triggers)
            FORK_TRIGGERS.each do |trigger|
                case triggers
                when Hash then return trigger if triggers.key?(trigger)
                when Array then return trigger if triggers.include?(trigger)
                when String then return trigger if triggers == trigger
                end
            end
            nil
        end

        def gated_by_label?(triggers, fork_trigger)
            return false unless triggers.is_a?(Hash)

            config = triggers[fork_trigger]
            return false unless config.is_a?(Hash)

            types = config["types"]
            return false unless types.is_a?(Array)

            # Safe if ONLY label-based types (no code-execution types like opened/synchronize)
            safe_types = %w[labeled unlabeled]
            (types - safe_types).empty?
        end
    end
end

module Rules
    class AiConfigInjection < Base
        def name = "ai-config-injection"
        def description = "AI tool runs on PR checkout code with attacker-controlled config"
        def severity = :critical

        PR_TRIGGERS = %w[pull_request pull_request_target].freeze

        AI_TOOL_ACTION_PATTERNS = [
            /\banthropics\/claude/i,
            /\bgithub\/copilot/i,
            /\baider[_-]ai\//i,
            /\bcursor\//i,
            /\bcline\//i,
            /\bcontinue[_-]dev\//i,
            /\bwindsurf\//i,
            /\bcodex\//i,
            /\bsweep[_-]ai\//i,
            /\bdevin\//i,
        ].freeze

        AI_TOOL_COMMANDS = [
            /\bclaude\b/,
            /\baider\b/,
            /\bcursor\s+(review|fix|chat|ask|compose|run)\b/,
            /\bcopilot\b/,
            /\bsgpt\b/,
            /\bcline\b/,
            /\bcontinue\s+(chat|review|fix|ask|suggest|generate|dev)\b/,
            /\bwindsurf\b/,
            /\bcodex\b/,
            /\bdevin\b/,
        ].freeze

        SANITIZATION_DIRS = %w[
            .claude/
            .cursor/
            .continue/
            .github/copilot/
        ].freeze

        SANITIZATION_FILES = %w[
            .mcp.json
            CLAUDE.md
            .cursorrules
            .aider.conf.yml
            .aiderignore
            .copilot-instructions.md
            .clinerules
            .windsurfrules
            .continue/config.json
        ].freeze

        SANITIZATION_PATHS = (SANITIZATION_DIRS + SANITIZATION_FILES).freeze

        SANITIZATION_FIX = "Add a sanitization step after checkout: " \
            "rm -rf .claude/ .cursor/ .continue/ .github/copilot/ && " \
            "rm -f .mcp.json .cursorrules .aider.conf.yml .aiderignore " \
            ".copilot-instructions.md CLAUDE.md .clinerules .windsurfrules " \
            ".continue/config.json"

        def check(workflow)
            findings = []
            triggers = workflow.triggers

            pr_triggers = detect_pr_triggers(triggers)
            return findings if pr_triggers.empty?

            workflow.jobs.each do |_job_id, job|
                pr_triggers.each do |pr_trigger|
                    is_prt = (pr_trigger == "pull_request_target")
                    pr_checkout_found = false
                    sanitized = false

                    workflow.steps(job).each do |step|
                        if !pr_checkout_found && pr_code_checkout?(step, is_prt)
                            pr_checkout_found = true
                            sanitized = false
                            next
                        end

                        next unless pr_checkout_found

                        if sanitization_step?(step)
                            sanitized = true
                            next
                        end

                        if ai_tool_step?(step) && !sanitized && !isolated_working_dir?(step)
                            tool_name = identify_ai_tool(step)
                            sev = is_prt ? :critical : :high

                            code = step["uses"] ? "uses: #{step["uses"]}" : step["run"]&.lines&.first&.strip
                            line = if step["uses"]
                                workflow.line_of(/uses:\s*#{Regexp.escape(step["uses"])}/) || 0
                            elsif step["run"]
                                first_line = step["run"].lines.first&.strip
                                first_line ? (workflow.line_of(/#{Regexp.escape(first_line[0..40])}/) || 0) : 0
                            else
                                0
                            end

                            findings << Finding.new(
                                rule: name,
                                severity: sev,
                                file: workflow.filename,
                                line: line,
                                code: code,
                                message: "#{tool_name} runs on PR checkout code (#{pr_trigger} trigger) " \
                                    "— attacker-controlled AI config files execute arbitrary code",
                                fix: SANITIZATION_FIX
                            )
                        end
                    end
                end
            end

            findings
        end

        private

        def detect_pr_triggers(triggers)
            trigger_list = case triggers
                when Hash then triggers.keys.map(&:to_s)
                when Array then triggers.map(&:to_s)
                when String then [triggers]
                else []
            end

            PR_TRIGGERS.select { |t| trigger_list.include?(t) }
        end

        def pr_code_checkout?(step, is_prt)
            return false unless step["uses"]&.include?("checkout")

            with = step["with"] || {}
            ref = with["ref"]&.to_s || ""

            if is_prt
                ref.match?(/\bgithub\.event\.pull_request\.head\b/) ||
                    ref.match?(/\bgithub\.head_ref\b/)
            else
                ref.empty? ||
                    ref.match?(/\bgithub\.event\.pull_request\.head\b/) ||
                    ref.match?(/\bgithub\.head_ref\b/) ||
                    ref.match?(/\bgithub\.ref\b/)
            end
        end

        def ai_tool_step?(step)
            ai_tool_action?(step["uses"]) || ai_tool_command?(step["run"])
        end

        def ai_tool_action?(uses)
            return false unless uses
            AI_TOOL_ACTION_PATTERNS.any? { |p| uses.match?(p) }
        end

        def ai_tool_command?(run)
            return false unless run
            AI_TOOL_COMMANDS.any? { |p| run.match?(p) }
        end

        def sanitization_step?(step)
            run = step["run"]
            return false unless run
            return false unless run.match?(/\brm\b/)
            SANITIZATION_PATHS.any? { |path| run.include?(path) }
        end

        def isolated_working_dir?(step)
            wd = step["working-directory"] || step.dig("with", "working-directory")
            return false unless wd
            !wd.strip.empty? && wd.strip != "."
        end

        def identify_ai_tool(step)
            if step["uses"]
                case step["uses"]
                when /claude/i then "Claude Code"
                when /copilot/i then "GitHub Copilot"
                when /aider/i then "Aider"
                when /cursor/i then "Cursor"
                when /cline/i then "Cline"
                when /continue[_-]dev/i then "Continue"
                when /windsurf/i then "Windsurf"
                when /codex/i then "Codex"
                when /devin/i then "Devin"
                else "AI tool (#{step["uses"]})"
                end
            elsif step["run"]
                case step["run"]
                when /\bclaude\b/ then "Claude Code"
                when /\bcopilot\b/ then "GitHub Copilot"
                when /\baider\b/ then "Aider"
                when /\bcursor\s+(review|fix|chat|ask|compose|run)\b/ then "Cursor"
                when /\bsgpt\b/ then "Shell GPT"
                when /\bcline\b/ then "Cline"
                when /\bcontinue\s+(chat|review|fix|ask|suggest|generate|dev)\b/ then "Continue"
                when /\bwindsurf\b/ then "Windsurf"
                when /\bcodex\b/ then "Codex"
                when /\bdevin\b/ then "Devin"
                else "AI tool"
                end
            else
                "AI tool"
            end
        end
    end
end

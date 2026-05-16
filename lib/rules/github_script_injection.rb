module Rules
  class GithubScriptInjection < Base
    def name = "github-script-injection"
    def description = "Attacker-controllable ${{ }} expression in actions/github-script"
    def severity = :critical

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
      github.actor
      github.triggering_actor
    ].freeze

    PATTERN = /\$\{\{\s*(#{DANGEROUS_CONTEXTS.map { |c| Regexp.escape(c) }.join('|')})/

    def check(workflow)
      findings = []

      workflow.raw_lines.each_with_index do |line, idx|
        line_num = idx + 1
        next unless line.match?(PATTERN)
        next unless in_github_script_block?(workflow, line_num)

        match = line.match(PATTERN)
        next unless match

        findings << finding(workflow,
          line: line_num,
          code: line.strip,
          message: "Attacker-controllable expression ${{ #{match[1]} }} in actions/github-script — JavaScript injection risk",
          fix: "Use context.payload instead: context.payload.pull_request.title"
        )
      end

      findings
    end

    private

    def in_github_script_block?(workflow, target_line)
      in_script = false
      script_indent = nil

      (target_line - 1).downto([target_line - 30, 0].max) do |i|
        content = workflow.raw_lines[i]
        next unless content

        # Found script: key — check if we're within a github-script step
        if content.match?(/^\s+script:\s*[\|>]?\s*$/) || content.match?(/^\s+script:\s+\S/)
          in_script = true
          script_indent = content[/^\s*/].length
          # Now look further up for the uses: actions/github-script line
          i.downto([i - 15, 0].max) do |j|
            step_line = workflow.raw_lines[j]
            next unless step_line
            return true if step_line.match?(/uses:\s*actions\/github-script/)
            # Stop if we hit another step boundary
            break if step_line.match?(/^\s+-\s+(name|uses|run|if|id):/)
          end
          return false
        end

        # If we hit a different key at the same or lower indent, we're outside the block
        if content.match?(/^\s+(uses|run|if|id|name|env|with):/) || content.match?(/^\s+-\s+(name|uses|run):/)
          return false
        end
      end

      false
    end
  end
end

module Rules
  class ShellInjectionExpr < Base
    def name = "shell-injection-expr"
    def description = "Attacker-controllable ${{ }} expression in run: block"
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
      github.head_ref
    ].freeze

    PATTERN = /\$\{\{\s*(#{DANGEROUS_CONTEXTS.map { |c| Regexp.escape(c) }.join('|')})/

    def check(workflow)
      findings = []
      workflow.lines_of(PATTERN).each do |line_num|
        line = workflow.line_content(line_num)
        next unless in_run_block?(workflow, line_num)

        match = line.match(PATTERN)
        next unless match

        findings << finding(workflow,
          line: line_num,
          code: line.strip,
          message: "Attacker-controllable expression ${{ #{match[1]} }} in run: block — shell injection risk",
          fix: "Move to env: block and reference as $ENV_VAR in the shell"
        )
      end
      findings
    end

    private

    def in_run_block?(workflow, target_line)
      (target_line - 1).downto([target_line - 20, 0].max) do |i|
        content = workflow.raw_lines[i]
        return true if content&.match?(/^\s+run:\s*[\|>]?\s*$/) || content&.match?(/^\s+run:\s+\S/)
        return false if content&.match?(/^\s+uses:/) || content&.match?(/^\s+-\s+name:/)
      end
      false
    end
  end
end

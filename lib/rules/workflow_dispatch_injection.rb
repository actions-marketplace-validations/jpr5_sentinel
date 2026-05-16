module Rules
  class WorkflowDispatchInjection < Base
    def name = "workflow-dispatch-injection"
    def description = "User-controlled workflow_dispatch input in run: block"
    def severity = :high

    PATTERN = /\$\{\{\s*(?:inputs\.|github\.event\.inputs\.)/

    def check(workflow)
      findings = []

      workflow.lines_of(PATTERN).each do |line_num|
        line = workflow.line_content(line_num)
        next unless in_run_block?(workflow, line_num)

        match = line.match(/\$\{\{\s*((?:inputs|github\.event\.inputs)\.[^\s}]+)/)
        next unless match

        findings << finding(workflow,
          line: line_num,
          code: line.strip,
          message: "User-controlled input ${{ #{match[1]} }} in run: block — shell injection risk",
          fix: "Move to env: block and reference as $ENV_VAR"
        )
      end

      findings
    end

    private

    def in_run_block?(workflow, target_line)
      (target_line - 1).downto([target_line - 20, 0].max) do |i|
        content = workflow.raw_lines[i]
        return true if content&.match?(/^\s+run:\s*[\|>]?\s*$/) || content&.match?(/^\s+run:\s+\S/)
        return true if content&.match?(/^\s+-\s+run:\s*[\|>]?\s*$/) || content&.match?(/^\s+-\s+run:\s+\S/)
        return false if content&.match?(/^\s+(uses|with|if|id|name|env):/) || content&.match?(/^\s+-\s+name:/)
      end
      false
    end
  end
end

module Rules
  class OverlyBroadTriggers < Base
    def name = "overly-broad-triggers"
    def description = "Push or pull_request trigger without branch filter"
    def severity = :low

    def check(workflow)
      findings = []
      triggers = workflow.triggers

      return findings unless triggers.is_a?(Hash)

      %w[push pull_request].each do |trigger|
        config = triggers[trigger]
        next unless config

        if config == true || config.nil? || (config.is_a?(Hash) && !config.key?("branches") && !config.key?("tags"))
          line = workflow.line_of(/^\s+#{trigger}:/)
          findings << finding(workflow,
            line: line || 0,
            code: "#{trigger}:",
            message: "'#{trigger}' trigger with no branch filter — runs on all branches",
            fix: "Add branches: [main] to scope the trigger"
          )
        end
      end

      findings
    end
  end
end

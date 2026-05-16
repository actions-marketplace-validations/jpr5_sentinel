module Rules
  class ShellInjectionJq < Base
    def name = "shell-injection-jq"
    def description = "Shell variable interpolated in double-quoted jq/curl JSON argument"
    def severity = :critical

    ATTACKER_ENV_VARS = %w[
      PR_TITLE PR_BODY PR_AUTHOR HEAD_REF ISSUE_TITLE ISSUE_BODY COMMENT_BODY
      PR_HEAD_REF BRANCH_NAME
    ].freeze

    JQ_PATTERN = /jq\s+([a-zA-Z-]+\s+)*--arg\s+\w+\s+"[^"]*\$\{/
    CURL_JSON_PATTERN = /curl\s.*-d\s+"[^"]*\$\{/
    def check(workflow)
      findings = []

      workflow.raw_lines.each_with_index do |line, i|
        line_num = i + 1

        if line.match?(JQ_PATTERN)
          var_match = line.match(/\$\{(\w+)\}/)
          next unless var_match
          var_name = var_match[1]
          next unless potentially_attacker_controlled?(var_name)

          findings << finding(workflow,
            line: line_num,
            code: line.strip,
            message: "${#{var_name}} interpolated in double-quoted jq argument — $(command) executes via bash substitution",
            fix: "Use jq --arg: jq -nc --arg #{var_name.downcase} \"$#{var_name}\" '{text: $#{var_name.downcase}}'"
          )
        end

        if line.match?(CURL_JSON_PATTERN)
          var_match = line.match(/\$\{(\w+)\}/)
          next unless var_match
          var_name = var_match[1]
          next unless potentially_attacker_controlled?(var_name)

          findings << finding(workflow,
            line: line_num,
            code: line.strip,
            message: "${#{var_name}} interpolated in double-quoted curl JSON — command substitution risk",
            fix: "Build JSON payload with jq -nc --arg instead of string interpolation"
          )
        end
      end

      findings
    end

    private

    def potentially_attacker_controlled?(var_name)
      ATTACKER_ENV_VARS.any? { |v| var_name.upcase == v } ||
        var_name.match?(/^(PR_|ISSUE_|COMMENT_)?(TITLE|BODY|HEAD_REF|BRANCH_NAME|COMMENT_BODY|AUTHOR)$/i)
    end
  end
end

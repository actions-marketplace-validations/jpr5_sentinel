module Rules
  class MissingFrozenLockfile < Base
    def name = "missing-frozen-lockfile"
    def description = "Package install without lockfile enforcement"
    def severity = :medium

    INSTALL_WITHOUT_LOCK = /(?:npm|pnpm)\s+install(?!\s+(-g|--global|--frozen-lockfile|--ci))/

    def check(workflow)
      findings = []

      workflow.raw_lines.each_with_index do |line, i|
        next unless line.match?(INSTALL_WITHOUT_LOCK)
        next if line.match?(/--frozen-lockfile|--ci|npm ci/)
        next if line.strip.start_with?("#")

        findings << finding(workflow,
          line: i + 1,
          code: line.strip,
          message: "Package install without --frozen-lockfile — dependency resolution may differ from tested versions",
          fix: "Use pnpm install --frozen-lockfile or npm ci"
        )
      end

      findings
    end
  end
end

module Rules
  class UnpinnedActions < Base
    def name = "unpinned-actions"
    def description = "Action referenced by tag instead of SHA pin"
    def severity = :critical

    SHA_PATTERN = /@[0-9a-f]{40}\b/

    def check(workflow)
      findings = []
      workflow.uses_actions.each do |action|
        uses = action[:uses]
        next if uses.nil?
        next if uses.start_with?("./")          # local action
        next if uses.start_with?("docker://")    # handled by unpinned-docker-image
        next if uses.match?(SHA_PATTERN)

        findings << finding(workflow,
          line: action[:line] || 0,
          code: "uses: #{uses}",
          message: "Action '#{uses}' is not SHA-pinned — tag references are mutable",
          fix: "Pin to a commit SHA: uses: #{uses.split('@').first}@<commit-sha> # #{uses.split('@').last}"
        )
      end
      findings
    end
  end
end

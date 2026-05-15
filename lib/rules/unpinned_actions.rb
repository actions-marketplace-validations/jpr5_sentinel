module Rules
    class UnpinnedActions < Base
        def name = "unpinned-actions"
        def description = "Action referenced by tag instead of SHA pin"
        def severity = :critical

        SHA_PATTERN = /@[0-9a-f]{40}\b/
        FIRST_PARTY = %w[actions/ github/].freeze

        def check(workflow)
            findings = []
            workflow.uses_actions.each do |action|
                uses = action[:uses]
                next if uses.nil?
                next if uses.start_with?("./")
                next if uses.start_with?("docker://")
                next if uses.match?(SHA_PATTERN)

                first_party = FIRST_PARTY.any? { |prefix| uses.start_with?(prefix) }
                sev = first_party ? :medium : :critical

                findings << Finding.new(
                    rule: name,
                    severity: sev,
                    file: workflow.filename,
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

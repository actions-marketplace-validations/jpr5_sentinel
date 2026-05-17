module Rules
    class UnpinnedArtifact < Base
        def name = "unpinned-artifact"
        def description = "download-artifact without specific artifact name"
        def severity = :low

        DOWNLOAD_ARTIFACT_PATTERN = /\bactions\/download-artifact\b/

        def check(workflow)
            findings = []

            workflow.uses_actions.each do |action|
                uses = action[:uses]
                next unless uses&.match?(DOWNLOAD_ARTIFACT_PATTERN)

                step = action[:step]
                with_block = step["with"]
                has_name = with_block.is_a?(Hash) && with_block.key?("name") && !with_block["name"].nil? && with_block["name"].to_s.strip != ""

                unless has_name
                    findings << finding(workflow,
                        line: action[:line] || 0,
                        code: "uses: #{uses}",
                        message: "download-artifact without specific name downloads ALL artifacts — may include untrusted content",
                        fix: "Specify artifact name: in download-artifact to avoid downloading unintended artifacts"
                    )
                end
            end

            findings
        end
    end
end

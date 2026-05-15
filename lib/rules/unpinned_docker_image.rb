module Rules
  class UnpinnedDockerImage < Base
    def name = "unpinned-docker-image"
    def description = "Docker image referenced by :latest tag"
    def severity = :low

    def check(workflow)
      findings = []

      workflow.lines_of(/:latest\b/).each do |line_num|
        line = workflow.line_content(line_num)
        next unless line&.match?(/docker:\/\/.*:latest|image:.*:latest|uses:.*:latest/)

        findings << finding(workflow,
          line: line_num,
          code: line.strip,
          message: "Docker image uses :latest tag — mutable, not reproducible",
          fix: "Pin to a specific digest: image@sha256:..."
        )
      end

      findings
    end
  end
end

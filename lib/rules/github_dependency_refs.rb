module Rules
    class GithubDependencyRefs < Base
        def name = "github-dependency-refs"
        def description = "Direct GitHub commit/branch reference in package install"
        def severity = :medium

        # Matches: npm install github:owner/repo#sha, or git+https://github.com/... in run blocks
        GITHUB_DEP = /(?:npm|pnpm|yarn|bun)\s+(?:install|add)\s+.*(?:github:|git\+https:\/\/github\.com)/

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                next if line.strip.start_with?("#")

                if line.match?(GITHUB_DEP)
                    findings << finding(workflow,
                        line: i + 1,
                        code: line.strip,
                        message: "Package installed from GitHub commit/branch ref — bypasses registry integrity checks",
                        fix: "Install from the package registry instead of GitHub refs"
                    )
                end
            end

            findings
        end
    end
end

module Rules
    class DockerBuildArgSecrets < Base
        def name = "docker-build-arg-secrets"
        def description = "Secrets passed as Docker build-args (visible in image layers)"
        def severity = :medium

        def check(workflow)
            findings = []

            workflow.lines_of(/build-args:/).each do |line_num|
                (line_num..(line_num + 20)).each do |i|
                    break if i > workflow.raw_lines.length
                    line = workflow.line_content(i)
                    break if line&.match?(/^\s*\w+:/) && !line.match?(/^\s+["']?[A-Z_]+=/)

                    if line&.match?(/secrets\./)
                        findings << finding(workflow,
                            line: i,
                            code: line.strip,
                            message: "Secret in Docker build-arg — extractable via docker history",
                            fix: "Use --secret flag or RUN --mount=type=secret instead of build-arg"
                        )
                    end
                end
            end

            findings
        end
    end
end

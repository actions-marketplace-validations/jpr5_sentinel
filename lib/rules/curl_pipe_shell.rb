module Rules
    class CurlPipeShell < Base
        def name = "curl-pipe-shell"
        def description = "Remote script piped directly to shell without integrity check"
        def severity = :high

        PIPE_PATTERN = /curl\s.*\|\s*(sudo\s+)?(sh|bash|zsh|source|\.)/
        WGET_PIPE = /wget\s.*-O\s*-\s*\|\s*(sudo\s+)?(sh|bash|zsh)/

        def check(workflow)
            findings = []

            workflow.raw_lines.each_with_index do |line, i|
                next if line.strip.start_with?("#")

                if line.match?(PIPE_PATTERN) || line.match?(WGET_PIPE)
                    findings << finding(workflow,
                        line: i + 1,
                        code: line.strip,
                        message: "Remote script piped to shell — no integrity verification, mutable endpoint",
                        fix: "Download first, verify checksum, then execute; or use a pinned GitHub Action instead"
                    )
                end
            end

            findings
        end
    end
end

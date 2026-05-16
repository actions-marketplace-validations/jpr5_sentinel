require "json"

module Formatter
    class Json
        def format(repo:, workflow_count:, findings:)
            summary = Finding::SEVERITIES.each_with_object({}) { |s, h|
                h[s.to_s] = findings.count { |f| f.severity == s }
            }

            JSON.pretty_generate({
                repo: repo,
                workflows: workflow_count,
                findings: findings.sort.map(&:to_h),
                summary: summary
            })
        end
    end
end

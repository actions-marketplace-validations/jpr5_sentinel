require "net/http"
require "json"
require "uri"

module Bot
    module SlackAlert
        WEBHOOK_ENV = "SLACK_WEBHOOK_OSS_ALERTS"

        # Orgs whose repos trigger Slack alerts on critical findings.
        # Matches the KNOWN_ORGS list in bootstrap.rb.
        ORG_PREFIXES = %w[CopilotKit/ ag-ui-protocol/].freeze

        def self.enabled?
            url = ENV[WEBHOOK_ENV]
            url && !url.strip.empty?
        end

        def self.org_repo?(repo_name)
            return false unless repo_name
            ORG_PREFIXES.any? { |prefix| repo_name.start_with?(prefix) }
        end

        def self.format_message(repo:, findings:)
            count = findings.length
            rules = findings.map(&:rule).uniq
            severities = findings.map { |f| f.severity.to_s }.uniq.join(", ")

            lines = []
            lines << ":shield: *Sentinel alert* — #{count} critical finding#{"s" if count != 1} in `#{repo}`"
            lines << ""
            findings.each do |f|
                lines << "  - `#{f.file}:#{f.line}` #{f.rule} (#{f.severity}): #{f.message}"
            end
            lines << ""
            lines << "Rules: #{rules.join(", ")}"
            lines << "Severities: #{severities}"

            lines.join("\n")
        end

        # Post a Slack alert for critical findings on an org repo.
        # Returns nil if disabled or on error (never raises).
        def self.post(repo:, findings:)
            return nil unless enabled?

            text = format_message(repo: repo, findings: findings)
            payload = { text: text }.to_json

            uri = URI.parse(ENV[WEBHOOK_ENV])
            response = Net::HTTP.post_form(uri, "payload" => payload)
            unless response.is_a?(Net::HTTPSuccess)
                $stderr.puts "SlackAlert: webhook returned #{response.code} for #{repo} — finding NOT delivered"
            end
            response
        rescue => e
            $stderr.puts "Slack alert failed (non-fatal): #{e.message}"
            nil
        end
    end
end

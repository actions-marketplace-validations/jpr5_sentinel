require "json"
require_relative "../version"

module Formatter
    class Sarif
        def format(repo:, workflow_count:, findings:)
            sarif = {
                "$schema" => "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
                "version" => "2.1.0",
                "runs" => [{
                    "tool" => {
                        "driver" => {
                            "name" => "sentinel",
                            "informationUri" => "https://sentinel.copilotkit.dev",
                            "version" => Sentinel::VERSION,
                            "rules" => build_rules(findings)
                        }
                    },
                    "results" => findings.sort.map { |f| build_result(f) }
                }]
            }
            JSON.pretty_generate(sarif)
        end

        private

        def build_rules(findings)
            findings.map(&:rule).uniq.map do |rule_id|
                {
                    "id" => rule_id,
                    "shortDescription" => { "text" => rule_id },
                    "defaultConfiguration" => {
                        "level" => sarif_level(findings.find { |f| f.rule == rule_id }.severity)
                    }
                }
            end
        end

        def build_result(finding)
            {
                "ruleId" => finding.rule,
                "level" => sarif_level(finding.severity),
                "message" => { "text" => "#{finding.message}. Fix: #{finding.fix}" },
                "locations" => [{
                    "physicalLocation" => {
                        "artifactLocation" => {
                            "uri" => build_uri(finding),
                            "uriBaseId" => "%SRCROOT%"
                        },
                        "region" => {
                            "startLine" => [finding.line, 1].max
                        }
                    }
                }]
            }
        end

        def build_uri(finding)
            file = finding.file
            if file.include?("/") || file == "(missing)"
                file
            elsif file == "dependabot.yml"
                ".github/#{file}"
            else
                ".github/workflows/#{file}"
            end
        end

        def sarif_level(severity)
            case severity
            when :critical, :high then "error"
            when :medium then "warning"
            when :low then "note"
            else "none"
            end
        end
    end
end

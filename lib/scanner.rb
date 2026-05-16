require_relative "finding"
require_relative "workflow"
require_relative "rule_engine"
require_relative "github_client"
require_relative "local_client"
require_relative "clone_client"
require_relative "auto_fix"
require_relative "ai_fix"
require_relative "policy"
require_relative "formatter/terminal"
require_relative "formatter/json"
require_relative "formatter/sarif"

class Scanner
    def initialize(client:, formatter:, min_severity: :low, policy: nil)
        @client = client
        @formatter = formatter
        @min_severity = min_severity
        @policy = policy || Policy.new
        @engine = RuleEngine.new
    end

    def scan(repo)
        raw_workflows = @client.fetch_workflows(repo)

        workflows = raw_workflows.map { |w|
            Workflow.new(filename: w[:filename], content: w[:content])
        }

        dependabot = @client.fetch_dependabot_config(repo)
        has_zizmor = workflows.any? { |w| w.filename.match?(/zizmor/i) }
        has_dependabot_actions = dependabot_has_actions?(dependabot)

        findings = []

        workflows.each do |wf|
            next if wf.parse_error?
            findings.concat(@engine.scan(wf))
        end

        unless has_dependabot_actions
            findings << Finding.new(
                rule: "missing-dependabot",
                severity: :low,
                file: "dependabot.yml",
                line: 0,
                code: nil,
                message: "No Dependabot configuration for github-actions ecosystem",
                fix: "Add package-ecosystem: github-actions to .github/dependabot.yml"
            )
        end

        unless has_zizmor
            findings << Finding.new(
                rule: "missing-zizmor",
                severity: :low,
                file: "(missing)",
                line: 0,
                code: nil,
                message: "No zizmor static analysis workflow found",
                fix: "Add a security_zizmor.yml workflow for GitHub Actions static analysis"
            )
        end

        findings.select! { |f| severity_passes?(f.severity) }

        # Apply policy overrides
        if @policy.loaded?
            # Filter out ignored files
            findings.reject! { |f| @policy.ignored?(f.file) }

            # Filter out excepted findings
            findings.reject! { |f| @policy.excepted?(f) }

            # Apply rule severity overrides — :off removes, others change severity
            findings.map! { |f|
                override = @policy.rule_severity(f.rule)
                if override == :off
                    nil
                elsif override
                    Finding.new(**f.to_h.merge(severity: override))
                else
                    f
                end
            }.compact!

            # Re-apply severity filter after overrides
            findings.select! { |f| severity_passes?(f.severity) }
        end

        output = @formatter.format(
            repo: repo,
            workflow_count: workflows.length,
            findings: findings
        )

        { output: output, findings: findings, workflow_count: workflows.length }
    end

    def scan_org(org)
        repos = @client.fetch_repos(org)
        results = []

        repos.each do |repo|
            $stderr.puts "Scanning #{repo}..." if @formatter.is_a?(Formatter::Terminal)
            results << scan(repo)
        end

        results
    end

    private

    def dependabot_has_actions?(config)
        return false unless config.is_a?(Hash)
        updates = config["updates"]
        return false unless updates.is_a?(Array)
        updates.any? { |u| u["package-ecosystem"] == "github-actions" }
    end

    def severity_passes?(sev)
        (Finding::SEVERITY_ORDER[sev] || 99) <= (Finding::SEVERITY_ORDER[@min_severity] || 99)
    end
end

#!/usr/bin/env ruby

require "optparse"
require "json"
require_relative "../lib/scanner"
require_relative "config"
require_relative "search"
require_relative "state"
require_relative "pr_writer"

module Bot
    class ScannerBot
        def initialize(token:, pattern: "rotate", dry_run: false)
            @search = Search.new(token: token)
            @state = State.new
            @pr_writer = PrWriter.new(token: token)
            @scanner = build_scanner
            @pattern = pattern
            @dry_run = dry_run
            @summary = { scanned: 0, findings: 0, prs_opened: 0, skipped: 0, errors: 0 }
        end

        def run
            query = select_query
            $stderr.puts "Bot run: pattern=#{query[:pattern]} dry_run=#{@dry_run}"
            $stderr.puts "Query: #{query[:query]}"

            candidates = @search.find_candidates(query)
            $stderr.puts "Found #{candidates.length} candidate repos"

            candidates.each do |repo|
                if @state.rate_limit_reached?
                    $stderr.puts "Daily PR limit reached (#{Config::MAX_PRS_PER_DAY}), stopping"
                    break
                end

                if @state.already_processed?(repo[:full_name], query[:pattern])
                    @summary[:skipped] += 1
                    next
                end

                if @state.opted_out?(repo[:full_name])
                    @summary[:skipped] += 1
                    next
                end

                scan_and_fix(repo, query[:pattern])
            end

            @state.save
            print_summary
        end

        private

        def build_scanner
            client_class = GitHubClient
            formatter = Formatter::Json.new
            Scanner.new(client: client_class.new, formatter: formatter, min_severity: :critical)
        end

        def scan_and_fix(repo, pattern)
            $stderr.puts "Scanning #{repo[:full_name]} (#{repo[:stars]} stars)..."
            @summary[:scanned] += 1

            begin
                result = @scanner.scan(repo[:full_name])
                findings = result[:findings]
            rescue => e
                $stderr.puts "  Error scanning: #{e.message}"
                @summary[:errors] += 1
                return
            end

            # Filter to critical/high findings matching fixable rules
            critical_findings = findings.select { |f|
                Config::CRITICAL_RULES.include?(f.rule) && (f.critical? || f.high?)
            }

            @state.record_scan(repo[:full_name], critical_findings)

            if critical_findings.empty?
                $stderr.puts "  No critical findings"
                return
            end

            @summary[:findings] += critical_findings.length
            $stderr.puts "  Found #{critical_findings.length} critical findings"

            # Check for opt-out file
            gh_client = GitHubClient.new
            if gh_client.file_exists?(repo[:full_name], Config::OPT_OUT_FILE)
                opt_out_content = gh_client.fetch_file_content(repo[:full_name], Config::OPT_OUT_FILE)
                if opt_out_content
                    begin
                        opt_out_config = YAML.safe_load(opt_out_content)
                        if opt_out_config.is_a?(Hash) && opt_out_config["enabled"] == false
                            $stderr.puts "  Repo has opted out"
                            @state.record_opt_out(repo[:full_name])
                            @summary[:skipped] += 1
                            return
                        end
                    rescue
                        # Ignore YAML parse errors in opt-out file
                    end
                end
            end

            # Group findings by rule for PR creation
            findings_by_rule = critical_findings.group_by(&:rule)

            findings_by_rule.each do |rule, rule_findings|
                break if @state.rate_limit_reached?
                next if @state.already_processed?(repo[:full_name], rule)
                next unless Config::FIXABLE_RULES.include?(rule)

                create_fix_pr(repo, rule, rule_findings)
            end

            # For non-fixable critical findings, create advisory PRs
            findings_by_rule.each do |rule, rule_findings|
                break if @state.rate_limit_reached?
                next if @state.already_processed?(repo[:full_name], rule)
                next if Config::FIXABLE_RULES.include?(rule) # already handled above

                create_advisory_pr(repo, rule, rule_findings)
            end
        end

        def create_fix_pr(repo, rule, findings)
            first = findings.first
            branch = "sentinel/fix-#{rule}"
            title = "Security: Fix #{rule} in GitHub Actions workflows"

            body = build_pr_body(
                rule: rule,
                severity: first.severity.to_s,
                findings: findings,
                fix_description: "This PR applies automated fixes for the #{rule} vulnerability pattern.\n\n" \
                    "**Note:** Please review the changes carefully before merging. " \
                    "Automated fixes may need adjustment for your specific workflow configuration."
            )

            if @dry_run
                $stderr.puts "  [DRY RUN] Would create PR: #{title}"
                findings.each { |f| $stderr.puts "    - #{f.file}:#{f.line} #{f.message}" }
                return
            end

            # For now, create advisory-only PRs (auto_fix.rb integration is future work)
            # When auto_fix.rb exists, it would generate the fixed file contents here
            $stderr.puts "  Creating advisory PR for #{rule} (automated fixes coming soon)"
            create_advisory_pr(repo, rule, findings)
        end

        def create_advisory_pr(repo, rule, findings)
            first = findings.first
            branch = "sentinel/advisory-#{rule}"
            title = "Security Advisory: #{rule} detected in GitHub Actions workflows"

            body = build_pr_body(
                rule: rule,
                severity: first.severity.to_s,
                findings: findings,
                fix_description: "This is an advisory PR to raise awareness of a security issue.\n\n" \
                    "**Recommended action:** Review the findings below and apply fixes manually.\n\n" \
                    "Each finding includes a suggested fix in the details."
            )

            if @dry_run
                $stderr.puts "  [DRY RUN] Would create advisory PR: #{title}"
                findings.each { |f| $stderr.puts "    - #{f.file}:#{f.line} #{f.message}" }
                return
            end

            # Create a minimal PR with a README-like advisory file
            files = {
                ".github/SECURITY_ADVISORY_#{rule.upcase.gsub("-", "_")}.md" => build_advisory_content(rule, findings),
            }

            pr = @pr_writer.create_pr(
                repo: repo[:full_name],
                branch: branch,
                title: title,
                body: body,
                files: files,
            )

            if pr
                $stderr.puts "  Opened PR: #{pr["html_url"]}"
                @state.record_pr(repo[:full_name], pr["html_url"], rule)
                @summary[:prs_opened] += 1
            else
                $stderr.puts "  Failed to create PR for #{rule}"
                @summary[:errors] += 1
            end
        end

        def build_pr_body(rule:, severity:, findings:, fix_description:)
            finding_lines = findings.map { |f|
                "- **#{f.file}** line #{f.line}: #{f.message}"
            }.join("\n")

            <<~BODY
            ## Security: Fix #{rule} in GitHub Actions workflows

            This PR was automatically generated by [sentinel](https://github.com/CopilotKit/sentinel).

            ### What was found

            **#{severity}: #{rule}** (#{findings.length} finding#{"s" if findings.length > 1})

            #{finding_lines}

            ### What this PR does

            #{fix_description}

            ### Opt out

            To stop receiving PRs from this bot:
            - Close this PR (we won't re-open for this rule)
            - Or add `.github/workflow-scanner.yml` with `enabled: false`

            ---
            *[sentinel](https://github.com/CopilotKit/sentinel) | [Report false positive](https://github.com/CopilotKit/sentinel/issues)*
            BODY
        end

        def build_advisory_content(rule, findings)
            lines = ["# Security Advisory: #{rule}\n\n"]
            lines << "This file was added by [sentinel](https://github.com/CopilotKit/sentinel) "
            lines << "to raise awareness of a security issue in your GitHub Actions workflows.\n\n"
            lines << "## Findings\n\n"

            findings.each do |f|
                lines << "### #{f.file} (line #{f.line})\n\n"
                lines << "**Severity:** #{f.severity}\n"
                lines << "**Message:** #{f.message}\n"
                lines << "**Suggested fix:** #{f.fix}\n\n" if f.fix
            end

            lines << "\n## What to do\n\n"
            lines << "1. Review the findings above\n"
            lines << "2. Apply the suggested fixes to your workflow files\n"
            lines << "3. Delete this file\n"
            lines << "4. Merge or close this PR\n"

            lines.join
        end

        def select_query
            queries = Config::SEARCH_QUERIES

            if @pattern == "rotate"
                # Rotate through queries based on day-of-week
                index = Time.now.wday % queries.length
                queries[index]
            else
                match = queries.find { |q| q[:pattern] == @pattern }
                match || queries.find { |q| q[:pattern].start_with?(@pattern) } || queries.first
            end
        end

        def print_summary
            s = @summary
            $stderr.puts
            $stderr.puts "=== Bot Run Summary ==="
            $stderr.puts "  Repos scanned: #{s[:scanned]}"
            $stderr.puts "  Critical findings: #{s[:findings]}"
            $stderr.puts "  PRs opened: #{s[:prs_opened]}"
            $stderr.puts "  Skipped (processed/opted-out): #{s[:skipped]}"
            $stderr.puts "  Errors: #{s[:errors]}"

            state_summary = @state.summary
            $stderr.puts
            $stderr.puts "  Lifetime: #{state_summary[:total_repos]} repos tracked, " \
                "#{state_summary[:total_prs]} PRs opened, #{state_summary[:opt_outs]} opt-outs"
            $stderr.puts "  Today: #{state_summary[:prs_today]}/#{Config::MAX_PRS_PER_DAY} PRs"
        end
    end
end

# CLI entry point
if __FILE__ == $0
    options = { pattern: "rotate", dry_run: false }

    OptionParser.new do |opts|
        opts.banner = "Usage: ruby bot/scanner_bot.rb [options]"
        opts.separator ""
        opts.separator "Scan popular repos and open fix PRs for critical findings."
        opts.separator ""

        opts.on("--pattern PATTERN", "Vulnerability pattern to search (default: rotate)") do |p|
            options[:pattern] = p
        end

        opts.on("--dry-run", "Don't create PRs, just log what would happen") do
            options[:dry_run] = true
        end

        opts.on("-h", "--help", "Show this help message") do
            puts opts
            exit 0
        end
    end.parse!

    token = ENV["GITHUB_TOKEN"] or abort("GITHUB_TOKEN required")
    Bot::ScannerBot.new(token: token, **options).run
end

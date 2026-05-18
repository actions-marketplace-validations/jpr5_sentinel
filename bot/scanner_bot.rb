#!/usr/bin/env ruby

require "optparse"
require "json"
require "yaml"
require "securerandom"
require "uri"
require_relative "../lib/scanner"
require_relative "../lib/auto_fix"
require_relative "../lib/sha_resolver"
require_relative "audit"
require_relative "config"
require_relative "github_app_auth"
require_relative "search"
require_relative "state"
require_relative "pr_writer"
require_relative "repo_conventions"

module Bot
    class ScannerBot
        def initialize(token: nil, pattern: "rotate", dry_run: false, limit: nil)
            if ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"]
                @auth = GitHubAppAuth.new
                @token = token || ENV["GITHUB_TOKEN"]
                $stderr.puts "Using GitHub App authentication (sentinel-ci-scanner)"
            else
                @auth = nil
                @token = token || ENV["GITHUB_TOKEN"]
                $stderr.puts "Using PAT authentication"
            end

            # Search and scanner always use the PAT (GitHub Code Search requires user auth)
            @search = Search.new(token: @token)
            @state = State.new
            @pr_writer = PrWriter.new(token: @token)
            @scanner = build_scanner
            @audit = Audit.new
            @pattern = pattern
            @dry_run = dry_run
            @limit = limit
            @summary = { scanned: 0, findings: 0, prs_opened: 0, skipped: 0, errors: 0 }
        end

        def run
            query = select_query
            @audit.run_start(query[:pattern], @dry_run, @limit)
            $stderr.puts "Bot run: pattern=#{query[:pattern]} dry_run=#{@dry_run}"
            $stderr.puts "Query: #{query[:query]}"

            candidates = @search.find_candidates(query)
            $stderr.puts "Found #{candidates.length} candidate repos"

            candidates.each do |repo|
                break if @limit && @summary[:scanned] >= @limit

                if @state.rate_limit_reached?
                    $stderr.puts "Daily PR limit reached (#{Config::MAX_PRS_PER_DAY}), stopping"
                    break
                end

                if @state.already_processed?(repo[:full_name], query[:pattern])
                    @audit.skip(repo[:full_name], "already_processed")
                    @summary[:skipped] += 1
                    next
                end

                if @state.opted_out?(repo[:full_name])
                    @audit.skip(repo[:full_name], "opted_out")
                    @summary[:skipped] += 1
                    next
                end

                scan_and_fix(repo, query[:pattern])
            end

            @state.save
            @audit.run_end(@summary)
            print_summary
        end

        private

        def repo_conventions(repo_name)
            @_conventions_cache ||= {}
            @_conventions_cache[repo_name] ||= RepoConventions.new(token: @token).detect(repo_name)
        end

        def build_scanner
            formatter = Formatter::Json.new
            Scanner.new(client: GitHubClient.new(token: @token), formatter: formatter, min_severity: :critical)
        end

        # Per-repo token: prefer GitHub App installation token, fall back to PAT
        def pr_token_for(repo)
            if @auth
                @auth.token_for(repo) || @token
            else
                @token
            end
        end

        def has_open_sentinel_pr?(repo_name)
            gh_client = GitHubClient.new(token: @token)

            # Determine fork owner (our authenticated user)
            user = gh_client.api_get("/user") rescue nil
            return false unless user && user["login"]
            fork_owner = user["login"]

            repo_short = repo_name.split("/").last

            # Check if sentinel/security-fixes branch exists on our fork
            ref = gh_client.api_get("/repos/#{fork_owner}/#{repo_short}/git/ref/heads/sentinel/security-fixes") rescue nil
            return false unless ref

            # Check if there's an open PR from this branch
            prs = gh_client.api_get("/repos/#{repo_name}/pulls?head=#{fork_owner}:sentinel/security-fixes&state=open") rescue nil
            prs.is_a?(Array) && !prs.empty?
        end

        def check_api_rate_limit
            gh_client = GitHubClient.new(token: @token)
            result = gh_client.api_get("/rate_limit") rescue nil
            return nil unless result
            result.dig("resources", "core", "remaining")
        end

        def preflight_check(repo, fixed_files)
            # 1. Not opted out
            return false if @state.opted_out?(repo[:full_name])

            # 2. No existing open PR
            if has_open_sentinel_pr?(repo[:full_name])
                $stderr.puts "  Open Sentinel PR already exists, skipping"
                return false
            end

            # 3. All fixed YAML is valid
            fixed_files.each do |path, content|
                begin
                    YAML.safe_load(content)
                rescue YAML::SyntaxError => e
                    $stderr.puts "  YAML validation failed for #{path}: #{e.message}"
                    return false
                end
            end

            # 4. Rate limit has headroom
            rate = check_api_rate_limit
            if rate && rate < 500
                $stderr.puts "  API rate limit too low (#{rate} remaining), skipping"
                return false
            end

            true
        end

        def scan_and_fix(repo, pattern)
            $stderr.puts "Scanning #{repo[:full_name]} (#{repo[:stars]} stars)..."
            @summary[:scanned] += 1

            begin
                result = @scanner.scan(repo[:full_name])
                findings = result[:findings]
            rescue => e
                $stderr.puts "  Error scanning: #{e.message}"
                @audit.error(repo[:full_name], e.message)
                @summary[:errors] += 1
                return
            end

            # Skip repos that already use Sentinel
            gh_client = GitHubClient.new(token: @token)
            sentinel_config = gh_client.file_exists?(repo[:full_name], ".github/.sentinel-ci.yml")
            workflows = gh_client.fetch_workflows(repo[:full_name])
            sentinel_workflow = workflows.any? { |w| w[:content]&.match?(/uses:\s*jpr5\/sentinel/) }
            if sentinel_config || sentinel_workflow
                $stderr.puts "  Already uses Sentinel, skipping"
                @audit.skip(repo[:full_name], "already_uses_sentinel")
                @summary[:skipped] += 1
                return
            end

            # Filter to critical/high findings matching fixable rules
            critical_findings = findings.select { |f|
                Config::CRITICAL_RULES.include?(f.rule) && (f.critical? || f.high?)
            }

            @state.record_scan(repo[:full_name], critical_findings)
            @audit.scan(repo[:full_name], critical_findings.length)

            if critical_findings.empty?
                $stderr.puts "  No critical findings"
                return
            end

            @summary[:findings] += critical_findings.length
            $stderr.puts "  Found #{critical_findings.length} critical findings"

            # Check for opt-out file
            if gh_client.file_exists?(repo[:full_name], Config::OPT_OUT_FILE)
                opt_out_content = gh_client.fetch_file_content(repo[:full_name], Config::OPT_OUT_FILE)
                if opt_out_content
                    begin
                        opt_out_config = YAML.safe_load(opt_out_content)
                        if opt_out_config.is_a?(Hash) && opt_out_config["enabled"] == false
                            $stderr.puts "  Repo has opted out"
                            @audit.opt_out(repo[:full_name])
                            @state.record_opt_out(repo[:full_name])
                            @summary[:skipped] += 1
                            return
                        end
                    rescue
                        # Ignore YAML parse errors in opt-out file
                    end
                end
            end

            # Detect repo conventions (CLA, DCO, conventional commits, PR template)
            conventions = repo_conventions(repo[:full_name])

            # Skip if CLA required (we can't sign it automatically)
            if conventions[:cla]
                $stderr.puts "  Skipping: #{conventions[:cla]} CLA required"
                @summary[:skipped] += 1
                return
            end

            # Collect all fixes into one PR
            sha_resolver = ShaResolver.new(token: @token)

            signoff = conventions[:dco] ? Config::SIGNOFF_IDENTITY : nil

            fixed_files = {}
            fixed_findings = []    # findings that were auto-fixed
            advisory_findings = [] # findings that need manual review

            critical_findings.group_by(&:file).each do |file, file_findings|
                content = gh_client.fetch_file_content(repo[:full_name], ".github/workflows/#{file}")
                next unless content

                patched = content
                file_findings.sort_by { |f| -(f.line || 0) }.each do |finding|
                    if AutoFix.can_fix?(finding)
                        result = AutoFix.apply(finding, patched, sha_resolver: sha_resolver)
                        if result && result != patched
                            patched = result
                            fixed_findings << finding
                            @audit.fix(repo[:full_name], finding.rule, file)
                        else
                            advisory_findings << finding
                        end
                    else
                        advisory_findings << finding
                    end
                end

                if patched != content
                    fixed_files[".github/workflows/#{file}"] = patched
                end
            end

            # Nothing to do
            if fixed_files.empty? && advisory_findings.empty?
                $stderr.puts "  No actionable findings"
                return
            end

            # Build consolidated PR
            total = fixed_findings.length + advisory_findings.length
            branch = "sentinel/security-fixes"

            title = if conventions[:conventional_commits]
                "fix(ci): resolve #{total} security finding#{"s" if total != 1} in GitHub Actions workflows"
            else
                "Security: Fix #{total} finding#{"s" if total != 1} in GitHub Actions workflows"
            end

            if conventions[:pr_template]
                $stderr.puts "  Note: repo has PR template — PR may need manual edits"
            end

            body = build_consolidated_pr_body(
                repo: repo[:full_name],
                fixed_findings: fixed_findings,
                advisory_findings: advisory_findings
            )

            if @dry_run
                $stderr.puts "  [DRY RUN] Would create consolidated PR: #{title}"
                fixed_findings.each { |f| $stderr.puts "    [fix] #{f.file}:#{f.line} #{f.rule}" }
                advisory_findings.each { |f| $stderr.puts "    [advisory] #{f.file}:#{f.line} #{f.rule}" }
                return
            end

            # Pre-flight validation before creating PR
            pr_files = fixed_files.empty? ? advisory_only_files(advisory_findings) : fixed_files
            unless preflight_check(repo, pr_files)
                $stderr.puts "  Pre-flight check failed, skipping PR creation"
                @summary[:skipped] += 1
                return
            end

            repo_token = pr_token_for(repo[:full_name])
            writer = PrWriter.new(token: repo_token)
            pr = writer.create_pr(
                repo: repo[:full_name],
                branch: branch,
                title: title,
                body: body,
                files: pr_files,
                signoff: signoff
            )

            if pr
                $stderr.puts "  Opened PR: #{pr["html_url"]}"
                @audit.pr_created(repo[:full_name], pr["html_url"])
                # Record one PR per rule for state tracking
                (fixed_findings + advisory_findings).map(&:rule).uniq.each do |rule|
                    @state.record_pr(repo[:full_name], pr["html_url"], rule)
                end
                @summary[:prs_opened] += 1
            else
                $stderr.puts "  Failed to create PR"
                @audit.pr_failed(repo[:full_name], "create_pr_returned_nil")
                @summary[:errors] += 1
            end
        end

        def build_consolidated_pr_body(repo:, fixed_findings:, advisory_findings:)
            opt_out_token = generate_token(repo, "opt-out")
            adopt_token = generate_token(repo, "adopt")
            encoded_repo = URI.encode_www_form_component(repo)
            opt_out_url = "#{Config::BOT_URL}/opt-out?repo=#{encoded_repo}&token=#{opt_out_token}"
            adopt_url = "#{Config::BOT_URL}/adopt?repo=#{encoded_repo}&token=#{adopt_token}"

            total = fixed_findings.length + advisory_findings.length
            rules_hit = (fixed_findings + advisory_findings).map(&:rule).uniq

            body = "## Security: #{total} finding#{"s" if total != 1} across #{rules_hit.length} rule#{"s" if rules_hit.length != 1}\n\n"

            if fixed_findings.any?
                body += "### Fixed (deterministic, no AI)\n\n"
                fixed_findings.group_by(&:rule).each do |rule, findings|
                    body += "**#{rule}** — [What is this?](#{Config::BOT_URL}/rules/#{rule})\n"
                    findings.each { |f| body += "- `#{f.file}` line #{f.line}: #{f.message}\n" }
                    body += "\n"
                end
            end

            if advisory_findings.any?
                body += "### Requires manual review\n\n"
                advisory_findings.group_by(&:rule).each do |rule, findings|
                    body += "**#{rule}** — [What is this?](#{Config::BOT_URL}/rules/#{rule})\n"
                    findings.each do |f|
                        body += "- `#{f.file}` line #{f.line}: #{f.message}\n"
                        body += "  - Fix: #{f.fix}\n" if f.fix
                    end
                    body += "\n"
                end
            end

            body += "### How this was detected\n\n"
            body += "This finding was identified by deterministic pattern matching — no AI or machine learning "
            body += "was used in the detection. Sentinel uses static analysis rules that match known-vulnerable "
            body += "YAML patterns against a database of documented exploit vectors. Every finding maps to a "
            body += "specific, reproducible pattern. [Source code](https://github.com/jpr5/sentinel) is open for inspection.\n\n"

            body += "---\n"
            body += "<sub>&#x1f6e1;&#xfe0f; This PR was generated by [Sentinel](https://sentinel.copilotkit.dev), "
            body += "an open-source security scanner. "
            body += "[Why this PR?](https://medium.com/@jordanritter/security-hardening-github-workflows-at-scale-d291a33774e1) · "
            body += "Free, no tracking</sub>\n\n"
            body += "[&#x2705; Add Sentinel to this repo](#{adopt_url}) · "
            body += "[&#x1f6ab; Opt out of future PRs](#{opt_out_url})\n"

            body
        end

        def advisory_only_files(findings)
            content = "# Security Advisory\n\n"
            content += "Sentinel detected #{findings.length} security finding#{"s" if findings.length != 1} "
            content += "in your GitHub Actions workflows that require manual review.\n\n"

            findings.group_by(&:rule).each do |rule, rule_findings|
                content += "## #{rule}\n\n"
                rule_findings.each do |f|
                    content += "### #{f.file} (line #{f.line})\n\n"
                    content += "**Severity:** #{f.severity}\n"
                    content += "**Issue:** #{f.message}\n"
                    content += "**Fix:** #{f.fix}\n\n" if f.fix
                end
            end

            { ".github/SECURITY_ADVISORY.md" => content }
        end

        def generate_token(repo, action)
            token = SecureRandom.uuid
            @state.record_token(token, repo, action)
            token
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
    options = { pattern: "rotate", dry_run: true, limit: nil }

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

        opts.on("--live", "Enable live mode (creates real PRs). Requires SENTINEL_BOT_LIVE=true env var.") do
            if ENV["SENTINEL_BOT_LIVE"] != "true"
                abort("--live requires SENTINEL_BOT_LIVE=true environment variable as safety gate")
            end
            options[:dry_run] = false
        end

        opts.on("--limit N", Integer, "Max repos to scan (default: unlimited)") do |n|
            options[:limit] = n
        end

        opts.on("-h", "--help", "Show this help message") do
            puts opts
            exit 0
        end
    end.parse!

    # Safety default: live mode without explicit --limit caps at 5
    if !options[:dry_run] && options[:limit].nil?
        options[:limit] = 5
        $stderr.puts "Live mode: defaulting to --limit 5"
    end

    token = ENV["GITHUB_TOKEN"]
    unless token || (ENV["GITHUB_APP_ID"] && ENV["GITHUB_APP_PRIVATE_KEY"])
        abort("Either GITHUB_TOKEN or GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY required")
    end
    Bot::ScannerBot.new(token: token, **options).run
end

# TEMPORARY KILL SWITCH — remove when bot is ready for production
# Added 2026-05-18 after uncontrolled PR spam incident

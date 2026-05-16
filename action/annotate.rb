#!/usr/bin/env ruby

require "json"
require "net/http"
require "uri"
require "open3"

$LOAD_PATH.unshift("/scanner/lib")
require "finding"
require "auto_fix"
require "ai_fix"
require "sha_resolver"

SEVERITY_LEVELS = %w[critical high medium low].freeze

def severity_index(sev)
    SEVERITY_LEVELS.index(sev.to_s.downcase) || 3
end

def annotation_level(severity)
    case severity.to_s.downcase
    when "critical", "high" then "error"
    when "medium"           then "warning"
    else                         "notice"
    end
end

def sanitize_annotation(text)
    text.to_s.gsub(/[\r\n]/, " ").gsub("::", ": :").strip
end

def set_output(name, value)
    output_file = ENV["GITHUB_OUTPUT"]
    if output_file && !output_file.empty?
        File.open(output_file, "a") { |f| f.puts "#{name}=#{value}" }
    end
end

# Apply fixes to workflow files on disk.
# Returns an array of file paths that were modified.
def apply_fixes(findings, workspace, ai_fix: false, ai_key: nil)
    sha_resolver = ShaResolver.new
    fixed_files = []

    # Group findings by file so we apply fixes per-file
    by_file = findings.group_by { |f| f["file"] }

    by_file.each do |file, file_findings|
        # Resolve the on-disk path
        path = if file.start_with?(".github/")
            File.join(workspace, file)
        elsif file == "dependabot.yml"
            File.join(workspace, ".github", "dependabot.yml")
        else
            File.join(workspace, ".github", "workflows", file)
        end

        next unless File.exist?(path)

        content = File.read(path)
        original = content.dup
        modified = false

        # Sort findings by line descending so later-line fixes don't shift
        # earlier-line positions (each fix re-parses from current content)
        sorted = file_findings.sort_by { |f| -(f["line"] || 0) }

        sorted.each do |raw_finding|
            finding = Finding.new(
                rule:     raw_finding["rule"],
                severity: raw_finding["severity"].to_sym,
                file:     raw_finding["file"],
                line:     raw_finding["line"],
                code:     raw_finding["code"],
                message:  raw_finding["message"],
                fix:      raw_finding["fix"],
            )

            if AutoFix.can_fix?(finding)
                result = AutoFix.apply(finding, content, sha_resolver: sha_resolver)
                if result && result != content
                    content = result
                    modified = true
                    puts "  Fixed [#{finding.rule}] in #{file}:#{finding.line} (mechanical)"
                end
            elsif ai_fix && ai_key && !ai_key.empty?
                result = AiFix.apply(finding, content, api_key: ai_key)
                if result && result != content
                    content = result
                    modified = true
                    puts "  Fixed [#{finding.rule}] in #{file}:#{finding.line} (AI)"
                end
            end
        end

        if modified
            File.write(path, content)
            fixed_files << path
        end
    end

    fixed_files
end

# Push fixes directly to the PR's source branch.
def push_inline_fixes(workspace, branch, repo, token)
    Dir.chdir(workspace) do
        system("git", "config", "user.name", "sentinel[bot]")
        system("git", "config", "user.email", "sentinel[bot]@users.noreply.github.com")

        # Configure credential helper instead of embedding token in URL
        system("git", "remote", "set-url", "origin", "https://github.com/#{repo}.git",
               [:out, :err] => File::NULL)
        system("git", "config", "--local",
               "url.https://x-access-token:#{token}@github.com/.insteadOf",
               "https://github.com/",
               [:out, :err] => File::NULL)

        # Checkout the PR branch (we may be on the merge ref)
        system("git", "fetch", "origin", branch)
        system("git", "checkout", branch)

        system("git", "add", ".github/")

        unless system("git", "diff", "--cached", "--quiet")
            system("git", "commit", "-m",
                "fix: auto-fix workflow security findings\n\nApplied by Sentinel (https://github.com/jpr5/sentinel)")

            if system("git", "push", "origin", branch,
                      [:err] => File::NULL)
                puts "Pushed fixes to branch #{branch}"
            else
                $stderr.puts "Failed to push to #{branch}. Check repository permissions."
            end
        end
    end
end

# Create a new PR with the fixes applied to a fresh branch.
def create_fix_pr(workspace, repo, token)
    Dir.chdir(workspace) do
        branch = "sentinel/fix-#{Time.now.strftime('%Y%m%d-%H%M%S')}"

        system("git", "config", "user.name", "sentinel[bot]")
        system("git", "config", "user.email", "sentinel[bot]@users.noreply.github.com")

        # Configure credential helper instead of embedding token in URL
        system("git", "remote", "set-url", "origin", "https://github.com/#{repo}.git",
               [:out, :err] => File::NULL)
        system("git", "config", "--local",
               "url.https://x-access-token:#{token}@github.com/.insteadOf",
               "https://github.com/",
               [:out, :err] => File::NULL)

        system("git", "checkout", "-b", branch)
        system("git", "add", ".github/")

        unless system("git", "diff", "--cached", "--quiet")
            system("git", "commit", "-m",
                "fix: auto-fix workflow security findings\n\nApplied by Sentinel (https://github.com/jpr5/sentinel)")

            if system("git", "push", "origin", branch,
                      [:err] => File::NULL)
                create_pr_via_api(repo, branch, token)
                puts "Created fix PR from branch #{branch}"
            else
                $stderr.puts "Failed to push to #{branch}. Check repository permissions."
            end
        end
    end
end

def default_branch(repo, token)
    # Prefer the branch that triggered the workflow (for push events this is the default branch)
    ref = ENV["GITHUB_REF_NAME"]
    return ref if ref && !ref.empty?

    # Fallback: ask the GitHub API
    begin
        uri = URI("https://api.github.com/repos/#{repo}")
        req = Net::HTTP::Get.new(uri)
        req["Authorization"] = "Bearer #{token}"
        req["Accept"] = "application/vnd.github+json"
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        resp = http.request(req)
        if resp.code.to_i == 200
            branch = JSON.parse(resp.body)["default_branch"]
            return branch if branch && !branch.empty?
        end
    rescue StandardError
        # ignore — fall through to "main"
    end

    "main"
end

def create_pr_via_api(repo, branch, token)
    base = default_branch(repo, token)

    uri = URI("https://api.github.com/repos/#{repo}/pulls")
    req = Net::HTTP::Post.new(uri)
    req["Authorization"] = "Bearer #{token}"
    req["Accept"] = "application/vnd.github+json"
    req.body = JSON.generate({
        title: "fix: Sentinel auto-fix workflow security findings",
        head: branch,
        base: base,
        body: "## Auto-fix by Sentinel\n\nThis PR fixes security findings " \
              "detected by [Sentinel](https://github.com/jpr5/sentinel).\n\n" \
              "Please review the changes before merging."
    })

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    resp = http.request(req)

    if resp.code.to_i == 201
        pr_url = JSON.parse(resp.body)["html_url"]
        puts "PR created: #{pr_url}"
    else
        $stderr.puts "Failed to create PR: #{resp.code} #{resp.body}"
    end
end

# ── Main ──────────────────────────────────────────────────────────────────────

# Read inputs from environment (GitHub Actions sets INPUT_* vars)
severity  = (ENV["INPUT_SEVERITY"] || "high").downcase
fail_on   = (ENV["INPUT_FAIL_ON_FINDINGS"] || "true").downcase == "true"
workspace = ENV["GITHUB_WORKSPACE"] || "/github/workspace"

# Validate severity
unless SEVERITY_LEVELS.include?(severity)
    $stderr.puts "Invalid severity '#{severity}'. Must be one of: #{SEVERITY_LEVELS.join(', ')}"
    exit 2
end

# Run the scanner
cmd = [
    "ruby", "/scanner/bin/sentinel",
    "--local", workspace,
    "--format", "json",
    "--severity", severity,
]

stdout, stderr, status = Open3.capture3(*cmd)

unless status.success? || status.exitstatus == 1  # exit 1 = findings found, expected
    $stderr.puts "Scanner exited with code #{status.exitstatus}"
    $stderr.puts stderr unless stderr.empty?
    # Still try to parse output if we got any
end

# Parse JSON output
begin
    result = JSON.parse(stdout)
rescue JSON::ParserError => e
    $stderr.puts "Failed to parse scanner output: #{e.message}"
    $stderr.puts "Raw output: #{stdout}" unless stdout.empty?
    exit 2
end

findings = result["findings"] || []

# Load policy if present
policy_path = File.join(workspace, ".sentinel-ci.yml")
if File.exist?(policy_path)
    require "policy"
    policy = Policy.new(policy_path)

    if policy.errors.any?
        policy.errors.each { |e| $stderr.puts "Policy error: #{e}" }
    else
        puts "Loaded policy from .sentinel-ci.yml"

        # Filter findings per policy
        findings.reject! { |f|
            finding_obj = Finding.new(
                rule: f["rule"], severity: f["severity"].to_sym,
                file: f["file"], line: f["line"],
                code: f["code"], message: f["message"], fix: f["fix"]
            )

            rule_sev = policy.rule_severity(f["rule"])
            rule_sev == :off || policy.ignored?(f["file"]) || policy.excepted?(finding_obj)
        }

        # Apply severity overrides
        findings.each do |f|
            override = policy.rule_severity(f["rule"])
            f["severity"] = override.to_s if override && override != :off
        end
    end
end

# Emit GitHub annotations
findings.each do |f|
    level   = annotation_level(f["severity"])
    file    = f["file"]
    line    = f["line"] || 1
    rule    = f["rule"]
    message = f["message"]
    fix     = f["fix"]

    # Build the workflow file path for annotations
    # If the file doesn't already include path prefix, add it
    annotation_file = if file.start_with?(".github/")
        file
    elsif file == "dependabot.yml"
        ".github/dependabot.yml"
    else
        ".github/workflows/#{file}"
    end

    # Ensure line is at least 1 for annotations
    line = 1 if line.to_i < 1

    annotation = "[#{rule}] #{message}"
    annotation += ". Fix: #{fix}" if fix && !fix.empty?

    puts "::#{level} file=#{annotation_file},line=#{line}::#{sanitize_annotation(annotation)}"
end

# Print terminal-format summary
puts ""
puts "=" * 60
puts "  Workflow Security Scanner Results"
puts "=" * 60
puts ""

if findings.empty?
    puts "  No findings at severity '#{severity}' or above."
else
    # Group and display by severity
    SEVERITY_LEVELS.each do |sev|
        sev_findings = findings.select { |f| f["severity"] == sev }
        next if sev_findings.empty?

        puts "  #{sev.upcase} (#{sev_findings.length}):"
        sev_findings.each do |f|
            puts "    - #{f['rule']}  #{f['file']}:#{f['line']}"
            puts "      #{f['message']}"
            puts "      Fix: #{f['fix']}" if f["fix"] && !f["fix"].empty?
        end
        puts ""
    end
end

# Count by severity
critical_count = findings.count { |f| f["severity"] == "critical" }
high_count     = findings.count { |f| f["severity"] == "high" }
total_count    = findings.length

puts "  Total: #{total_count} findings (#{critical_count} critical, #{high_count} high)"
puts "=" * 60
puts ""

# Set outputs
set_output("findings-count", total_count)
set_output("critical-count", critical_count)
set_output("high-count", high_count)

# ── Fix mode ──────────────────────────────────────────────────────────────────

fixes_applied = 0

if ENV["INPUT_FIX"] == "true"
    event_name = ENV["GITHUB_EVENT_NAME"]
    head_ref   = ENV["GITHUB_HEAD_REF"]
    repo       = ENV["GITHUB_REPOSITORY"]
    token      = ENV["GITHUB_TOKEN"] || ENV["INPUT_GITHUB_TOKEN"]

    ai_key = ENV["INPUT_ANTHROPIC_KEY"]
    ai_fix = ai_key && !ai_key.empty?

    puts ""
    puts "Fix mode enabled — applying fixes..."
    puts ""

    fixed_files = apply_fixes(findings, workspace, ai_fix: ai_fix, ai_key: ai_key)
    fixes_applied = fixed_files.length

    if fixed_files.any?
        if event_name == "pull_request" && head_ref && !head_ref.empty?
            push_inline_fixes(workspace, head_ref, repo, token)
        else
            create_fix_pr(workspace, repo, token)
        end
    else
        puts "No fixable findings detected."
    end
end

set_output("fixes-applied", fixes_applied)

# Exit with failure if findings exist and fail-on-findings is true
if fail_on && total_count > 0
    $stderr.puts "Failing: #{total_count} finding(s) at severity '#{severity}' or above."
    exit 1
end

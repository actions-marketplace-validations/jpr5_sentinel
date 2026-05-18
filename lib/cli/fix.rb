require "optparse"
require_relative "../scanner"
require_relative "../auto_fix"
require_relative "../ai_fix"
require_relative "token_resolver"

options = {
    format: "terminal",
    severity: :low,
    dry_run: false,
    ai: false,
    model: nil,
    ai_key: nil,
}

parser = OptionParser.new do |opts|
    opts.banner = "Usage: sentinel fix [options] [REPO]"
    opts.separator ""
    opts.separator "Auto-fix security findings in GitHub Actions workflows."
    opts.separator ""
    opts.separator "Modes:"
    opts.separator "  sentinel fix --local PATH        Fix workflows in a local directory"
    opts.separator "  sentinel fix owner/repo           Clone, fix, and open a PR (requires GITHUB_TOKEN)"
    opts.separator ""

    opts.on("--format FORMAT", %w[terminal json], "Output format: terminal (default) or json") do |f|
        options[:format] = f
    end

    opts.on("--severity LEVEL", %i[critical high medium low],
            "Minimum severity: critical, high, medium, low (default: low)") do |s|
        options[:severity] = s
    end

    opts.on("--local PATH", "Scan a local directory instead of GitHub API") do |p|
        options[:local] = p
    end

    opts.on("--org ORG", "Scan all repos in a GitHub organization") do |o|
        options[:org] = o
    end

    opts.on("--token TOKEN", "GitHub API token (default: GITHUB_TOKEN env var)") do |t|
        options[:token] = t
    end

    opts.on("--dry-run", "Show diffs without writing files") do
        options[:dry_run] = true
    end

    opts.on("--ai", "Use AI-powered fixes for complex rules (requires API key)") do
        options[:ai] = true
    end

    opts.on("--model MODEL", "AI model to use (default: #{AiFix::DEFAULT_MODEL})") do |m|
        options[:model] = m
    end

    opts.on("--ai-key KEY", "API key for AI fixes (default: ANTHROPIC_API_KEY env var)") do |k|
        options[:ai_key] = k
    end

    opts.on("-h", "--help", "Show this help message") do
        puts opts
        exit 0
    end
end

begin
    parser.parse!
rescue OptionParser::InvalidArgument, OptionParser::InvalidOption => e
    $stderr.puts e.message
    $stderr.puts parser
    exit 2
end

repo = ARGV.shift

# --- Validate mode ---
modes = [options[:local], repo].compact
if modes.empty?
    $stderr.puts "Error: must specify --local PATH or a REPO argument (owner/repo)"
    $stderr.puts ""
    $stderr.puts "  sentinel fix --local ."
    $stderr.puts "  sentinel fix --local . --dry-run"
    $stderr.puts "  sentinel fix owner/repo"
    $stderr.puts ""
    exit 2
end

# --- Validate AI key if --ai is set ---
ai_key = nil
if options[:ai]
    ai_key = options[:ai_key] || ENV["ANTHROPIC_API_KEY"]
    if ai_key.nil? || ai_key.empty?
        $stderr.puts <<~MSG
            AI-powered fixes require an API key. Set ANTHROPIC_API_KEY or pass --ai-key:

              export ANTHROPIC_API_KEY=sk-ant-...
              sentinel fix --local . --ai

            AI fixes can handle: github-script-injection, cache-poisoning,
            excessive-permissions, build-publish-same-job, and 14 more rules
            that require understanding workflow intent.
        MSG
        exit 2
    end
end

# -----------------------------------------------------------------------
# Shared fix logic — operates on a workflows_dir, returns fix results
# -----------------------------------------------------------------------
def scan_and_fix(workflows_dir, scan_target, options, ai_key)
    $stderr.puts "Scanning..."

    client = LocalClient.new(File.dirname(File.dirname(workflows_dir)))
    formatter = Formatter::Terminal.new
    scanner = Scanner.new(client: client, formatter: formatter, min_severity: options[:severity])
    result = scanner.scan(scan_target)
    findings = result[:findings]

    mechanical = findings.select { |f| AutoFix.can_fix?(f) }
    ai_eligible = findings.select { |f| AiFix.can_fix?(f) }

    $stderr.puts "Found #{findings.length} findings (#{mechanical.length} mechanical, #{ai_eligible.length} AI-eligible)"
    $stderr.puts ""

    if mechanical.empty? && (!options[:ai] || ai_eligible.empty?)
        $stderr.puts "No fixable findings."
        return nil
    end

    # --- Read raw file contents ---
    all_fixable_files = (mechanical + (options[:ai] ? ai_eligible : [])).map(&:file).uniq
    file_contents = {}
    original_contents = {}
    all_fixable_files.each do |filename|
        path = File.join(workflows_dir, filename)
        if File.exist?(path)
            file_contents[filename] = File.read(path)
            original_contents[filename] = file_contents[filename].dup
        end
    end

    # --- Pass 1: Mechanical fixes ---
    mechanical_details = Hash.new { |h, k| h[k] = [] }
    mechanical_count = 0

    by_file_mechanical = mechanical.group_by(&:file)
    by_file_mechanical.each do |filename, file_findings|
        content = file_contents[filename]
        next unless content

        sorted = file_findings.sort_by { |f| -(f.line || 0) }

        sorted.each do |finding|
            content = AutoFix.apply(finding, content)

            detail = case finding.rule
            when "unpinned-actions"
                action_match = finding.code&.match(/uses:\s*(\S+)/)
                action_ref = action_match ? action_match[1] : finding.code
                "unpinned-actions: #{action_ref} pinned to SHA"
            when "shell-injection-expr"
                "shell-injection-expr: moved expression to env block"
            when "missing-persist-credentials"
                "missing-persist-credentials: added persist-credentials: false"
            when "workflow-dispatch-injection"
                "workflow-dispatch-injection: moved dispatch input to env block"
            when "missing-permissions"
                "missing-permissions: added permissions: contents: read"
            when "missing-timeouts"
                job_match = finding.message&.match(/job '([^']+)'/) || finding.message&.match(/job "([^"]+)"/)
                job_name = job_match ? job_match[1] : "job"
                "missing-timeouts: added timeout-minutes: 30 to #{job_name}"
            else
                "#{finding.rule}: applied fix"
            end

            mechanical_details[filename] << "  - #{detail}"
            mechanical_count += 1
        end

        file_contents[filename] = content
    end

    # --- Pass 2: AI fixes (if --ai is set) ---
    ai_details = Hash.new { |h, k| h[k] = [] }
    ai_count = 0
    ai_model = options[:model] || AiFix::DEFAULT_MODEL

    if options[:ai] && ai_key
        by_file_ai = ai_eligible.group_by(&:file)
        by_file_ai.each do |filename, file_findings|
            content = file_contents[filename]
            next unless content

            file_findings.each do |finding|
                $stderr.puts "  AI fixing #{finding.rule} in #{filename}:#{finding.line}..."
                fixed = AiFix.apply(finding, content, model: ai_model, api_key: ai_key)

                if fixed
                    content = fixed
                    ai_details[filename] << "  - #{finding.rule}: AI-generated fix applied"
                    ai_count += 1
                else
                    $stderr.puts "  AI fix failed for #{finding.rule} in #{filename}:#{finding.line}"
                end
            end

            file_contents[filename] = content
        end
    end

    # Skipped findings
    skipped = if options[:ai]
        []
    else
        ai_eligible
    end

    {
        file_contents: file_contents,
        original_contents: original_contents,
        mechanical_details: mechanical_details,
        mechanical_count: mechanical_count,
        ai_details: ai_details,
        ai_count: ai_count,
        skipped: skipped,
        findings: findings,
    }
end

# -----------------------------------------------------------------------
# Display fix summary
# -----------------------------------------------------------------------
def print_fix_summary(result, options)
    mechanical_details = result[:mechanical_details]
    ai_details = result[:ai_details]
    ai_count = result[:ai_count]
    mechanical_count = result[:mechanical_count]
    skipped = result[:skipped]

    puts ""

    mechanical_details.each do |filename, details|
        action = options[:dry_run] ? "Would fix (mechanical)" : "Fixed (mechanical)"
        puts "#{action}: .github/workflows/#{filename}"
        details.each { |d| puts d }
        puts ""
    end

    ai_details.each do |filename, details|
        action = options[:dry_run] ? "Would fix (AI)" : "Fixed (AI)"
        puts "#{action}: .github/workflows/#{filename}"
        details.each { |d| puts d }
        puts ""
    end

    if skipped.any?
        puts "Skipped (no auto-fix, no --ai):"
        skipped.each do |f|
            puts "  - #{f.rule}: #{f.file}:#{f.line}"
        end
        puts ""
    end

    if ai_count > 0
        puts "⚠ AI-generated fixes should be reviewed before merging."
        puts ""
    end

    total_fixed = mechanical_count + ai_count
    manual_count = skipped.length
    verb = options[:dry_run] ? "would be fixed" : "fixed"
    parts = ["#{total_fixed} findings #{verb}"]
    parts << "#{mechanical_count} mechanical" if mechanical_count > 0 && ai_count > 0
    parts << "#{ai_count} AI" if ai_count > 0
    parts << "#{manual_count} require manual review" if manual_count > 0
    puts parts.join(", ") + "."
end

# -----------------------------------------------------------------------
# Show unified diffs for changed files
# -----------------------------------------------------------------------
def show_diffs(result, workflows_dir)
    require "tempfile"
    require "open3"

    all_changed_files = (result[:mechanical_details].keys + result[:ai_details].keys).uniq

    all_changed_files.each do |filename|
        original = result[:original_contents][filename] || ""
        content = result[:file_contents][filename]

        next unless content && content != original

        orig_file = Tempfile.new(["orig", ".yml"])
        fixed_file = Tempfile.new(["fixed", ".yml"])
        begin
            orig_file.write(original)
            orig_file.flush
            fixed_file.write(content)
            fixed_file.flush

            diff_output, _ = Open3.capture2("diff", "-u", orig_file.path, fixed_file.path)
            diff_output.sub!(/^--- .*$/, "--- .github/workflows/#{filename}")
            diff_output.sub!(/^\+\+\+ .*$/, "+++ .github/workflows/#{filename} (fixed)")
            puts diff_output
            puts ""
        ensure
            orig_file.close!
            fixed_file.close!
        end
    end
end

# -----------------------------------------------------------------------
# Write fixed files to disk
# -----------------------------------------------------------------------
def write_fixes(result, workflows_dir)
    all_changed_files = (result[:mechanical_details].keys + result[:ai_details].keys).uniq

    all_changed_files.each do |filename|
        path = File.join(workflows_dir, filename)
        original = File.exist?(path) ? File.read(path) : ""
        content = result[:file_contents][filename]

        next unless content && content != original
        File.write(path, content)
    end
end

# -----------------------------------------------------------------------
# Build files hash for PrWriter (path => content)
# -----------------------------------------------------------------------
def changed_files_for_pr(result)
    files = {}
    all_changed = (result[:mechanical_details].keys + result[:ai_details].keys).uniq

    all_changed.each do |filename|
        original = result[:original_contents][filename] || ""
        content = result[:file_contents][filename]
        next unless content && content != original
        files[".github/workflows/#{filename}"] = content
    end

    files
end

# -----------------------------------------------------------------------
# Build PR body from fix results
# -----------------------------------------------------------------------
def build_fix_pr_body(result)
    lines = []
    lines << "## Security fixes applied by sentinel"
    lines << ""
    lines << "This PR was automatically generated by [sentinel](https://github.com/jpr5/sentinel)."
    lines << ""
    lines << "### Changes"
    lines << ""

    result[:mechanical_details].each do |filename, details|
        lines << "**#{filename}** (mechanical):"
        details.each { |d| lines << d }
        lines << ""
    end

    result[:ai_details].each do |filename, details|
        lines << "**#{filename}** (AI-assisted):"
        details.each { |d| lines << d }
        lines << ""
    end

    if result[:ai_count] > 0
        lines << "> **Note:** AI-generated fixes should be reviewed carefully before merging."
        lines << ""
    end

    lines << "---"
    lines << "*[sentinel](https://github.com/jpr5/sentinel) | [Report false positive](https://github.com/jpr5/sentinel/issues)*"

    lines.join("\n")
end

# =======================================================================
# Main flow
# =======================================================================

if options[:local]
    # ---- Local fix flow (existing behavior) ----
    local_path = options[:local]
    workflows_dir = File.join(File.expand_path(local_path), ".github", "workflows")

    unless File.directory?(workflows_dir)
        $stderr.puts "Error: no .github/workflows directory found at #{local_path}"
        exit 2
    end

    result = scan_and_fix(workflows_dir, local_path, options, ai_key)
    exit 0 unless result

    if options[:dry_run]
        show_diffs(result, workflows_dir)
    else
        write_fixes(result, workflows_dir)
    end

    print_fix_summary(result, options)

else
    # ---- Remote fix flow ----
    token = TokenResolver.resolve(options)

    clone = CloneClient.new

    begin
        $stderr.puts "Cloning #{repo}..."
        workflows = clone.fetch_workflows(repo)

        if workflows.empty?
            $stderr.puts "No workflows found in #{repo}."
            exit 0
        end

        workflows_dir = File.join(clone.tmpdir, ".github", "workflows")

        result = scan_and_fix(workflows_dir, repo, options, ai_key)
        exit 0 unless result

        pr_files = changed_files_for_pr(result)
        total_fixed = result[:mechanical_count] + result[:ai_count]

        if pr_files.empty?
            $stderr.puts "No changes produced by fixes."
            exit 0
        end

        # Always show what was fixed
        show_diffs(result, workflows_dir)
        print_fix_summary(result, options)

        if options[:dry_run]
            $stderr.puts ""
            $stderr.puts "Dry run — no PR created."
            exit 0
        end

        if token
            # Fork + PR flow using PrWriter
            require_relative "../../bot/pr_writer"

            branch = "sentinel/fix-#{Time.now.strftime("%Y%m%d-%H%M%S")}"
            title = "Security: Fix #{total_fixed} finding#{"s" if total_fixed != 1} in GitHub Actions workflows"
            body = build_fix_pr_body(result)

            $stderr.puts ""
            $stderr.puts "Creating PR on #{repo}..."

            pr_writer = Bot::PrWriter.new(token: token)
            pr = pr_writer.create_pr(
                repo: repo,
                branch: branch,
                title: title,
                body: body,
                files: pr_files,
            )

            if pr
                puts ""
                puts "PR created: #{pr["html_url"]}"
            else
                $stderr.puts "Failed to create PR. The diff has been shown above."
                $stderr.puts "You can apply these fixes manually."
                exit 1
            end
        else
            # No token — show instructions
            puts ""
            puts "Fixes applied locally. To submit as a PR, set GITHUB_TOKEN:"
            puts ""
            puts "  export GITHUB_TOKEN=$(gh auth token)"
            puts "  sentinel fix #{repo}"
            puts ""
        end
    ensure
        clone.cleanup
    end
end

exit 0

require "optparse"
require_relative "../scanner"
require_relative "../auto_fix"

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

    opts.on("--model MODEL", "AI model to use (default: claude-sonnet-4-20250514)") do |m|
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

# --- AI stub ---
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
    else
        $stderr.puts "AI-powered fixes coming in v0.2.0."
        exit 0
    end
end

# --- Local-only for now ---
unless options[:local]
    $stderr.puts "Error: fix currently requires --local PATH"
    $stderr.puts ""
    $stderr.puts "  sentinel fix --local ."
    $stderr.puts "  sentinel fix --local . --dry-run"
    $stderr.puts ""
    $stderr.puts "Remote fix (PR creation) is handled by 'sentinel bot'."
    exit 2
end

repo = options[:local]
workflows_dir = File.join(File.expand_path(repo), ".github", "workflows")

unless File.directory?(workflows_dir)
    $stderr.puts "Error: no .github/workflows directory found at #{repo}"
    exit 2
end

# --- Scan ---
$stderr.puts "Scanning..."

client = LocalClient.new(repo)
formatter = Formatter::Terminal.new
scanner = Scanner.new(client: client, formatter: formatter, min_severity: options[:severity])
result = scanner.scan(repo)
findings = result[:findings]

fixable = findings.select { |f| AutoFix.can_fix?(f) }
unfixable = findings.reject { |f| AutoFix.can_fix?(f) }

$stderr.puts "Found #{findings.length} findings (#{fixable.length} auto-fixable)"
$stderr.puts ""

if fixable.empty?
    $stderr.puts "No auto-fixable findings."
    exit 0
end

# --- Group findings by file ---
by_file = fixable.group_by(&:file)

# --- Read raw file contents ---
file_contents = {}
by_file.each_key do |filename|
    path = File.join(workflows_dir, filename)
    if File.exist?(path)
        file_contents[filename] = File.read(path)
    end
end

# --- Apply fixes ---
fixed_count = 0
fixed_details = Hash.new { |h, k| h[k] = [] }

by_file.each do |filename, file_findings|
    content = file_contents[filename]
    next unless content

    original = content.dup

    # Sort findings by line descending so line numbers stay valid as we modify
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

        fixed_details[filename] << "  - #{detail}"
        fixed_count += 1
    end

    if content != original
        if options[:dry_run]
            # Show unified diff
            require "tempfile"
            orig_file = Tempfile.new(["orig", ".yml"])
            fixed_file = Tempfile.new(["fixed", ".yml"])
            begin
                orig_file.write(original)
                orig_file.flush
                fixed_file.write(content)
                fixed_file.flush

                diff_output = `diff -u #{orig_file.path} #{fixed_file.path} 2>&1`
                # Replace temp paths with meaningful names
                diff_output.sub!(/^--- .*$/, "--- .github/workflows/#{filename}")
                diff_output.sub!(/^\+\+\+ .*$/, "+++ .github/workflows/#{filename} (fixed)")
                puts diff_output
                puts ""
            ensure
                orig_file.close!
                fixed_file.close!
            end
        else
            # Write the fixed file
            path = File.join(workflows_dir, filename)
            File.write(path, content)
        end
    end
end

# --- Output summary ---
puts ""

by_file.each_key do |filename|
    next unless fixed_details.key?(filename)
    action = options[:dry_run] ? "Would fix" : "Fixed"
    puts "#{action}: .github/workflows/#{filename}"
    fixed_details[filename].each { |d| puts d }
    puts ""
end

if unfixable.any?
    puts "Skipped (no auto-fix available):"
    unfixable.each do |f|
        puts "  - #{f.rule}: #{f.file}:#{f.line}"
    end
    puts ""
end

manual_count = unfixable.length
verb = options[:dry_run] ? "would be fixed" : "fixed"
puts "#{fixed_count} findings #{verb}, #{manual_count} require manual review."

exit 0

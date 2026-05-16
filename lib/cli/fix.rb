require "optparse"
require_relative "../scanner"
require_relative "../auto_fix"
require_relative "../ai_fix"

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

mechanical = findings.select { |f| AutoFix.can_fix?(f) }
ai_eligible = findings.select { |f| AiFix.can_fix?(f) }

$stderr.puts "Found #{findings.length} findings (#{mechanical.length} mechanical, #{ai_eligible.length} AI-eligible)"
$stderr.puts ""

if mechanical.empty? && (!options[:ai] || ai_eligible.empty?)
    $stderr.puts "No fixable findings."
    exit 0
end

# --- Read raw file contents ---
all_fixable_files = (mechanical + (options[:ai] ? ai_eligible : [])).map(&:file).uniq
file_contents = {}
all_fixable_files.each do |filename|
    path = File.join(workflows_dir, filename)
    if File.exist?(path)
        file_contents[filename] = File.read(path)
    end
end

# --- Pass 1: Mechanical fixes ---
mechanical_details = Hash.new { |h, k| h[k] = [] }
mechanical_count = 0

by_file_mechanical = mechanical.group_by(&:file)
by_file_mechanical.each do |filename, file_findings|
    content = file_contents[filename]
    next unless content

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

# --- Write or diff ---
all_changed_files = (mechanical_details.keys + ai_details.keys).uniq

all_changed_files.each do |filename|
    path = File.join(workflows_dir, filename)
    original = File.exist?(path) ? File.read(path) : ""
    content = file_contents[filename]

    next unless content && content != original

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
        File.write(path, content)
    end
end

# --- Output summary ---
puts ""

# Mechanical fixes
mechanical_details.each do |filename, details|
    action = options[:dry_run] ? "Would fix (mechanical)" : "Fixed (mechanical)"
    puts "#{action}: .github/workflows/#{filename}"
    details.each { |d| puts d }
    puts ""
end

# AI fixes
ai_details.each do |filename, details|
    action = options[:dry_run] ? "Would fix (AI)" : "Fixed (AI)"
    puts "#{action}: .github/workflows/#{filename}"
    details.each { |d| puts d }
    puts ""
end

# Skipped findings (not mechanical, no --ai or AI not available)
skipped = if options[:ai]
    # With --ai, only findings that failed AI fix are skipped
    ai_eligible.select { |f| !ai_details.values.flatten.any? { |d| d.include?(f.rule) } }
    # Simpler: nothing is "skipped" category when --ai is on; failures already reported
    []
else
    ai_eligible
end

if skipped.any?
    puts "Skipped (no auto-fix, no --ai):"
    skipped.each do |f|
        puts "  - #{f.rule}: #{f.file}:#{f.line}"
    end
    puts ""
end

# Warning for AI fixes
if ai_count > 0
    puts "⚠ AI-generated fixes should be reviewed before merging."
    puts ""
end

# Summary line
total_fixed = mechanical_count + ai_count
manual_count = skipped.length
verb = options[:dry_run] ? "would be fixed" : "fixed"
parts = ["#{total_fixed} findings #{verb}"]
parts << "#{mechanical_count} mechanical" if mechanical_count > 0 && ai_count > 0
parts << "#{ai_count} AI" if ai_count > 0
parts << "#{manual_count} require manual review" if manual_count > 0
puts parts.join(", ") + "."

exit 0

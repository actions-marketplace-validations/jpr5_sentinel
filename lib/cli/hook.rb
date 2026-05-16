require "optparse"
require "fileutils"

HOOK_MARKER_BEGIN = "# --- sentinel pre-commit hook begin ---"
HOOK_MARKER_END   = "# --- sentinel pre-commit hook end ---"

HOOK_SCRIPT = <<~'BASH'
#!/usr/bin/env bash
# --- sentinel pre-commit hook begin ---
# Sentinel pre-commit hook — scans workflow files for security issues

# Only run if workflow files are staged
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.github/workflows/.*\.ya?ml$')
if [ -z "$STAGED" ]; then
  exit 0
fi

# Run sentinel scan
if command -v sentinel &>/dev/null; then
  sentinel scan --local . --severity high
  exit $?
elif command -v ruby &>/dev/null; then
  ruby -e 'require "rubygems"; gem "sentinel-ci"; load Gem.bin_path("sentinel-ci", "sentinel")' scan --local . --severity high 2>/dev/null
  exit $?
else
  echo "Warning: sentinel not found. Install with: gem install sentinel-ci"
  exit 0
fi
# --- sentinel pre-commit hook end ---
BASH

action = ARGV.shift

case action
when "install"
    git_root = `git rev-parse --show-toplevel 2>/dev/null`.strip
    if git_root.empty?
        $stderr.puts "Error: not inside a git repository"
        exit 2
    end

    hook_path = File.join(git_root, ".git", "hooks", "pre-commit")

    if File.exist?(hook_path)
        existing = File.read(hook_path)
        if existing.include?(HOOK_MARKER_BEGIN)
            $stderr.puts "Sentinel pre-commit hook is already installed."
            exit 0
        end
        # Append sentinel section to existing hook
        File.open(hook_path, "a") do |f|
            f.puts ""
            f.puts HOOK_SCRIPT.lines[1..].join  # skip shebang when appending
        end
    else
        FileUtils.mkdir_p(File.dirname(hook_path))
        File.write(hook_path, HOOK_SCRIPT)
    end

    File.chmod(0o755, hook_path)
    puts "Pre-commit hook installed. Sentinel will scan workflow files before each commit."

when "uninstall"
    git_root = `git rev-parse --show-toplevel 2>/dev/null`.strip
    if git_root.empty?
        $stderr.puts "Error: not inside a git repository"
        exit 2
    end

    hook_path = File.join(git_root, ".git", "hooks", "pre-commit")

    unless File.exist?(hook_path)
        $stderr.puts "No pre-commit hook found."
        exit 0
    end

    content = File.read(hook_path)

    unless content.include?(HOOK_MARKER_BEGIN)
        $stderr.puts "No sentinel hook found in pre-commit."
        exit 0
    end

    # Remove the sentinel section
    lines = content.lines
    in_sentinel = false
    filtered = lines.reject do |line|
        if line.strip == HOOK_MARKER_BEGIN
            in_sentinel = true
            true
        elsif line.strip == HOOK_MARKER_END
            in_sentinel = false
            true
        else
            in_sentinel
        end
    end

    # Remove trailing blank lines left behind
    filtered.pop while filtered.last&.strip&.empty?

    if filtered.empty? || filtered.all? { |l| l.strip.empty? || l.strip == "#!/usr/bin/env bash" }
        File.delete(hook_path)
    else
        File.write(hook_path, filtered.join)
    end

    puts "Pre-commit hook removed."

when "run"
    # Check if workflow files are staged
    staged = `git diff --cached --name-only --diff-filter=ACM 2>/dev/null`.strip
    workflow_files = staged.split("\n").select { |f| f.match?(%r{\.github/workflows/.*\.ya?ml$}) }

    if workflow_files.empty?
        exit 0
    end

    # Run the scan
    require_relative "../scanner"

    client = LocalClient.new(".")
    formatter = Formatter::Terminal.new
    scanner = Scanner.new(client: client, formatter: formatter, min_severity: :high)
    result = scanner.scan(".")

    puts result[:output]

    has_findings = result[:findings].any? { |f| f.critical? || f.high? }
    exit(has_findings ? 1 : 0)

when nil, "-h", "--help"
    puts <<~HELP
    Usage: sentinel hook <action>

    Actions:
        install     Install git pre-commit hook
        uninstall   Remove the pre-commit hook
        run         Run the hook check (used by hook managers)

    Examples:
        sentinel hook install
        sentinel hook uninstall
        sentinel hook run
    HELP
    exit 0
else
    $stderr.puts "Unknown hook action: #{action}"
    $stderr.puts "Run 'sentinel hook --help' for usage"
    exit 2
end

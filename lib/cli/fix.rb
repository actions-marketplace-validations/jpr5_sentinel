require "optparse"

options = {}

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

    opts.on("--token TOKEN", "GitHub API token (default: GITHUB_TOKEN env var)") do |t|
        options[:token] = t
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

$stderr.puts "Auto-fix coming soon."
$stderr.puts ""
$stderr.puts "For now, use the Ruby API directly:"
$stderr.puts ""
$stderr.puts "  require 'sentinel-ci'"
$stderr.puts "  AutoFix.apply(path: '.github/workflows')"
$stderr.puts ""

exit 0

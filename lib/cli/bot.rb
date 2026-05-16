require "optparse"
require_relative "../../bot/scanner_bot"

options = {
    pattern: "rotate",
    dry_run: false,
}

parser = OptionParser.new do |opts|
    opts.banner = "Usage: sentinel bot [options]"
    opts.separator ""
    opts.separator "Run the Sentinel PR bot to scan and file issues."
    opts.separator ""

    opts.on("--pattern PATTERN", "Search pattern (default: rotate)") do |p|
        options[:pattern] = p
    end

    opts.on("--dry-run", "Show what would be done without making changes") do
        options[:dry_run] = true
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

token = options[:token] || ENV["GITHUB_TOKEN"]
unless token
    $stderr.puts "Error: GitHub token required. Set GITHUB_TOKEN or use --token."
    exit 2
end

bot = Bot::ScannerBot.new(
    token: token,
    pattern: options[:pattern],
    dry_run: options[:dry_run],
)

bot.run

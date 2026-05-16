require "optparse"
require_relative "../scanner"

options = {
    format: "terminal",
    severity: :low,
}

parser = OptionParser.new do |opts|
    opts.banner = "Usage: sentinel scan [options] [REPO]"
    opts.separator ""
    opts.separator "Scan GitHub Actions workflows for security issues."
    opts.separator ""

    opts.on("--format FORMAT", %w[terminal json sarif], "Output format: terminal (default), json, or sarif") do |f|
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

modes = [options[:local], options[:org], repo].compact
if modes.empty?
    $stderr.puts "Error: must specify --local PATH, --org ORG, or a REPO argument"
    $stderr.puts parser
    exit 2
elsif modes.length > 1
    $stderr.puts "Error: specify only one of --local, --org, or REPO"
    $stderr.puts parser
    exit 2
end

def resolve_token(options)
    return options[:token] if options[:token]
    return ENV["GITHUB_TOKEN"] if ENV["GITHUB_TOKEN"]

    gh_path = `which gh 2>/dev/null`.strip
    if !gh_path.empty? && system("gh", "auth", "status", [:out, :err] => File::NULL)
        token = `gh auth token 2>/dev/null`.strip
        return token unless token.empty?
    end

    nil
end

token = resolve_token(options)

client = if options[:local]
    LocalClient.new(options[:local])
elsif options[:org]
    unless token
        $stderr.puts "Error: --org requires a GitHub token to list repos."
        $stderr.puts ""
        $stderr.puts "  export GITHUB_TOKEN=$(gh auth token)"
        $stderr.puts "  sentinel scan --org #{options[:org]}"
        exit 2
    end
    GitHubClient.new(token: token)
else
    if token
        GitHubClient.new(token: token)
    else
        CloneClient.new
    end
end

formatter = case options[:format]
when "json"  then Formatter::Json.new
when "sarif" then Formatter::Sarif.new
else              Formatter::Terminal.new
end

scanner = Scanner.new(client: client, formatter: formatter, min_severity: options[:severity])

all_findings = []

begin
    if options[:local]
        result = scanner.scan(options[:local])
        puts result[:output]
        all_findings.concat(result[:findings])
    elsif options[:org]
        results = scanner.scan_org(options[:org])

        if options[:format] == "json"
            combined = results.map { |r| JSON.parse(r[:output]) }
            puts JSON.pretty_generate(combined)
        else
            results.each { |r| puts r[:output] }

            totals = Hash.new(0)
            results.each do |r|
                r[:findings].each { |f| totals[f.severity] += 1 }
            end

            summary = Finding::SEVERITIES
                .select { |s| totals[s] > 0 }
                .map { |s| "#{totals[s]} #{s}" }
                .join(", ")

            total = results.sum { |r| r[:findings].length }
            $stderr.puts "\nOrg scan complete: #{results.length} repos, #{total} findings (#{summary})"
        end

        results.each { |r| all_findings.concat(r[:findings]) }
    else
        result = scanner.scan(repo)
        puts result[:output]
        all_findings.concat(result[:findings])
    end

    has_critical_or_high = all_findings.any? { |f| f.critical? || f.high? }
    exit(has_critical_or_high ? 1 : 0)
ensure
    client.cleanup if client.respond_to?(:cleanup)
end

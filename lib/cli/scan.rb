require "optparse"
require_relative "../scanner"
require_relative "token_resolver"

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
        options[:severity_explicit] = true
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

token = TokenResolver.resolve(options)

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

# Load .sentinel-ci.yml policy config
policy = if options[:local]
    policy_path = File.join(options[:local], ".sentinel-ci.yml")
    File.exist?(policy_path) ? Policy.new(policy_path) : Policy.new
elsif !options[:org] && client.respond_to?(:fetch_file_content)
    # Remote repo — try to download .sentinel-ci.yml
    content = client.fetch_file_content(repo, ".sentinel-ci.yml")
    if content
        require "tmpdir"
        policy_path = File.join(Dir.tmpdir, "sentinel-policy-#{Process.pid}.yml")
        File.write(policy_path, content)
        policy = Policy.new(policy_path)
        File.delete(policy_path) rescue nil
        policy
    else
        Policy.new
    end
else
    Policy.new
end

if policy.errors.any?
    policy.errors.each { |e| $stderr.puts "Policy error: #{e}" }
    exit 2
end

# Use policy severity as default if not explicitly overridden on CLI
unless options[:severity_explicit]
    options[:severity] = policy.min_severity if policy.loaded?
end

formatter = case options[:format]
when "json"  then Formatter::Json.new
when "sarif" then Formatter::Sarif.new
else              Formatter::Terminal.new
end

scanner = Scanner.new(client: client, formatter: formatter, min_severity: options[:severity], policy: policy)

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

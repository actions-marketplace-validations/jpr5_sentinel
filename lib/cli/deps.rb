require "optparse"
require_relative "../scanner"
require_relative "../supply_chain"
require_relative "token_resolver"

options = {
    format: "terminal",
}

parser = OptionParser.new do |opts|
    opts.banner = "Usage: sentinel deps [options] [REPO]"
    opts.separator ""
    opts.separator "Map third-party action dependencies, maintainers, and risk factors."
    opts.separator ""

    opts.on("--format FORMAT", %w[terminal json], "Output format: terminal (default) or json") do |f|
        options[:format] = f
    end

    opts.on("--local PATH", "Analyze a local directory instead of GitHub API") do |p|
        options[:local] = p
    end

    opts.on("--org ORG", "Analyze all repos in a GitHub organization") do |o|
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

# Build a client to fetch workflow files
client = if options[:local]
    LocalClient.new(options[:local])
elsif options[:org]
    unless token
        $stderr.puts "Error: --org requires a GitHub token to list repos."
        $stderr.puts ""
        $stderr.puts "  export GITHUB_TOKEN=$(gh auth token)"
        $stderr.puts "  sentinel deps --org #{options[:org]}"
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

# Collect workflows
repos_to_scan = if options[:org]
    client.fetch_repos(options[:org])
else
    [options[:local] || repo]
end

all_actions = []

begin
    repos_to_scan.each do |r|
        raw_workflows = client.fetch_workflows(r)
        workflows = raw_workflows.map { |w|
            Workflow.new(filename: w[:filename], content: w[:content])
        }

        chain = SupplyChain.new(token: token)
        all_actions.concat(chain.analyze(workflows))
    end
ensure
    client.cleanup if client.respond_to?(:cleanup)
end

# Deduplicate across repos (for org scans)
seen = {}
all_actions = all_actions.reject { |a| seen.key?(a[:repo]) ? true : (seen[a[:repo]] = true; false) }

if options[:format] == "json"
    puts JSON.pretty_generate(all_actions.map { |a|
        {
            repo: a[:repo],
            owner: a[:owner],
            first_party: a[:first_party],
            refs: a[:refs],
            used_in: a[:used_in],
            stars: a[:stars],
            archived: a[:archived],
            last_push: a[:last_push],
            owner_type: a[:owner_type],
            license: a[:license],
            description: a[:description],
            risk_score: a[:risk_score],
            risk_factors: a[:risk_factors],
        }
    })
    exit 0
end

# Terminal output
target = options[:org] || options[:local] || repo
puts ""
puts "Third-party action dependencies for #{target}:"
puts ""

# Separate first-party and third-party
third_party = all_actions.reject { |a| a[:first_party] }
first_party = all_actions.select { |a| a[:first_party] }

# Sort by risk score descending (highest risk first), nil scores at end
sorted = third_party.sort_by { |a| -(a[:risk_score] || 0) }

# Risk bar helper
risk_bar = ->(score) {
    return "    " unless score
    filled = [score, 4].min
    "█" * filled + "░" * (4 - filled)
}

# Format stars
format_stars = ->(stars) {
    return "  —" unless stars
    if stars >= 1000
        "#{(stars / 1000.0).round(1)}k".rjust(5)
    else
        stars.to_s.rjust(5)
    end
}

# Format pinned status
pinned = ->(refs) {
    return "N/A" unless refs
    refs.all? { |r| r.match?(/[0-9a-f]{40}/) } ? "Yes" : "No"
}

# Format used_in
format_used_in = ->(used_in) {
    return "" unless used_in
    used_in.map { |u| "#{u[:file]}:#{u[:line]}" }.join(", ")
}

# Header
printf "  %-4s  %-38s %5s   %-6s  %-6s  %s\n", "RISK", "ACTION", "STARS", "OWNER", "PINNED", "USED IN"

# Third-party actions
sorted.each do |a|
    owner_type = a[:owner_type] || (a[:first_party] ? "GitHub" : "?")
    printf "  %s  %-38s %s   %-6s  %-6s  %s\n",
        risk_bar.call(a[:risk_score]),
        a[:repo],
        format_stars.call(a[:stars]),
        owner_type,
        pinned.call(a[:refs]),
        format_used_in.call(a[:used_in])
end

# First-party actions
first_party.each do |a|
    printf "  %s  %-38s %5s   %-6s  %-6s  %s\n",
        "░░░░",
        a[:repo],
        "—".rjust(5),
        "GitHub",
        pinned.call(a[:refs]),
        "(first-party, skipped)"
end

# Risk factors section
risky = sorted.select { |a| a[:risk_factors] && !a[:risk_factors].empty? }
if risky.any?
    puts ""
    puts "Risk factors:"
    risky.each do |a|
        puts "  #{a[:repo]}: #{a[:risk_factors].join(', ')}"
    end
end

# Summary
puts ""
high_risk = third_party.count { |a| (a[:risk_score] || 0) >= 5 }
medium_risk = third_party.count { |a| s = a[:risk_score] || 0; s >= 3 && s < 5 }
low_risk = third_party.count { |a| (a[:risk_score] || 0) < 3 }

# If no enrichment happened (no token), just show count
if third_party.all? { |a| a[:risk_score].nil? }
    puts "#{third_party.length} third-party actions found (set GITHUB_TOKEN for risk scoring)"
else
    parts = ["#{third_party.length} third-party action#{'s' unless third_party.length == 1}"]
    parts << "#{high_risk} high risk" if high_risk > 0
    parts << "#{medium_risk} medium risk" if medium_risk > 0
    parts << "#{low_risk} low risk" if low_risk > 0
    puts parts.join(", ")
end

puts ""
exit 0

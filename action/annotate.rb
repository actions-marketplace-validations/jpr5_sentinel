#!/usr/bin/env ruby

require "json"
require "open3"

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

def set_output(name, value)
    output_file = ENV["GITHUB_OUTPUT"]
    if output_file && !output_file.empty?
        File.open(output_file, "a") { |f| f.puts "#{name}=#{value}" }
    end
end

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

    puts "::#{level} file=#{annotation_file},line=#{line}::#{annotation}"
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

# Exit with failure if findings exist and fail-on-findings is true
if fail_on && total_count > 0
    $stderr.puts "Failing: #{total_count} finding(s) at severity '#{severity}' or above."
    exit 1
end

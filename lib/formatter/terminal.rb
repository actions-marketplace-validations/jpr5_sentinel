module Formatter
  class Terminal
    COLORS = {
      critical: "\e[31m",   # red
      high:     "\e[33m",   # yellow
      medium:   "\e[36m",   # cyan
      low:      "\e[90m",   # dim
      reset:    "\e[0m",
      bold:     "\e[1m",
      green:    "\e[32m",
    }.freeze

    def format(repo:, workflow_count:, findings:)
      lines = []
      lines << ""
      lines << "#{c(:bold)}=== #{repo} (#{workflow_count} workflows) ===#{c(:reset)}"
      lines << ""

      if findings.empty?
        lines << "  #{c(:green)}No findings.#{c(:reset)}"
      else
        findings.sort.each do |f|
          sev = f.severity.to_s.upcase.ljust(10)
          lines << "  #{c(f.severity)}#{sev}#{c(:reset)} #{c(:bold)}#{f.rule}#{c(:reset)}  #{f.file}:#{f.line}"
          lines << "            #{f.message}"
          lines << "            #{c(:green)}Fix: #{f.fix}#{c(:reset)}" if f.fix
          lines << ""
        end

        summary = Finding::SEVERITIES.map { |s|
          count = findings.count { |f| f.severity == s }
          next nil if count == 0
          "#{c(s)}#{count} #{s}#{c(:reset)}"
        }.compact.join(", ")

        lines << "  --- Summary: #{summary} ---"
      end

      lines << ""
      lines.join("\n")
    end

    private

    def c(name) = COLORS[name] || ""
  end
end

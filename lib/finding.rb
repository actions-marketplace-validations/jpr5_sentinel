Finding = Struct.new(:rule, :severity, :file, :line, :code, :message, :fix, keyword_init: true)

class Finding
    SEVERITIES = %i[critical high medium low].freeze
    SEVERITY_ORDER = SEVERITIES.each_with_index.to_h.freeze

    def <=>(other)
        SEVERITY_ORDER[severity] <=> SEVERITY_ORDER[other.severity]
    end

    def critical? = severity == :critical
    def high?     = severity == :high
    def medium?   = severity == :medium
    def low?      = severity == :low

    def to_h
        {
            rule: rule,
            severity: severity.to_s,
            file: file,
            line: line,
            code: code,
            message: message,
            fix: fix
        }
    end
end

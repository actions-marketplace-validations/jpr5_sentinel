require "yaml"

class Policy
    KNOWN_TOP_KEYS = %w[severity rules policy ignore exceptions].freeze
    KNOWN_POLICY_KEYS = %w[require recommend].freeze

    attr_reader :config, :errors

    def initialize(path = nil)
        @path = path
        @config = {}
        @errors = []
        load_config if @path && File.exist?(@path)
    end

    def loaded? = !@config.empty?

    # Severity override — returns the configured minimum severity or default
    def min_severity
        sev = @config["severity"]
        return :low unless sev
        sev.to_sym
    end

    # Rule severity override or :off
    def rule_severity(rule_name)
        rules = @config["rules"] || {}
        return nil unless rules.key?(rule_name)
        override = rules[rule_name]
        # YAML parses "off" as boolean false
        return :off if override == false || override.to_s == "off"
        override.to_sym
    end

    # Should this file be ignored?
    def ignored?(filename)
        patterns = @config["ignore"] || []
        patterns.any? { |pat| File.fnmatch(pat, filename, File::FNM_PATHNAME) }
    end

    # Is this finding excepted?
    def excepted?(finding)
        exceptions = @config["exceptions"] || []
        exceptions.any? { |ex|
            ex["rule"] == finding.rule &&
            (ex["file"].nil? || ex["file"] == finding.file)
        }
    end

    # Policy requirements
    def required_policies = (@config.dig("policy", "require") || [])
    def recommended_policies = (@config.dig("policy", "recommend") || [])

    private

    def load_config
        raw = YAML.safe_load(File.read(@path))
        unless raw.is_a?(Hash)
            @errors << "#{@path}: expected a YAML mapping, got #{raw.class}"
            return
        end

        @config = raw
        validate!
    rescue YAML::SyntaxError => e
        @errors << "#{@path}: YAML syntax error: #{e.message}"
    end

    def validate!
        unknown_top = @config.keys - KNOWN_TOP_KEYS
        unknown_top.each { |k| @errors << "Unknown key '#{k}' in #{@path}" }

        if @config["severity"]
            unless %w[critical high medium low].include?(@config["severity"].to_s)
                @errors << "Invalid severity '#{@config["severity"]}' — must be critical, high, medium, or low"
            end
        end

        if @config["rules"]
            known_rules = load_known_rules
            @config["rules"].each do |rule, val|
                unless known_rules.include?(rule)
                    @errors << "Unknown rule '#{rule}' in rules section"
                end
                normalized = val == false ? "off" : val.to_s
                unless %w[critical high medium low off].include?(normalized)
                    @errors << "Invalid severity '#{val}' for rule '#{rule}' — must be critical, high, medium, low, or off"
                end
            end
        end

        if @config["policy"]
            unknown_policy = @config["policy"].keys - KNOWN_POLICY_KEYS
            unknown_policy.each { |k| @errors << "Unknown key '#{k}' in policy section" }
        end

        (@config["exceptions"] || []).each_with_index do |ex, i|
            unless ex.is_a?(Hash) && ex["rule"]
                @errors << "Exception ##{i + 1} missing required 'rule' field"
            end
            unless ex.is_a?(Hash) && ex["reason"]
                @errors << "Exception ##{i + 1} missing required 'reason' field — no silent suppressions"
            end
        end
    end

    def load_known_rules
        rules = []
        rules_dir = File.join(File.dirname(__FILE__), "rules")
        if File.directory?(rules_dir)
            require_relative "rules/base"
            Dir[File.join(rules_dir, "*.rb")].each do |f|
                next if File.basename(f) == "base.rb"
                require f
            end
            Rules.constants.each do |const|
                klass = Rules.const_get(const)
                next unless klass.is_a?(Class) && klass < Rules::Base
                rules << klass.new.name
            end
        end
        rules + %w[missing-dependabot missing-zizmor]
    end
end

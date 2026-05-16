class RuleEngine
    attr_reader :rules

    def initialize
        @rules = []
        load_rules
    end

    def scan(workflow)
        findings = []
        @rules.each do |rule|
            begin
                findings.concat(rule.check(workflow))
            rescue => e
                $stderr.puts "Rule #{rule.name} failed on #{workflow.filename}: #{e.message}"
            end
        end
        findings.sort
    end

    private

    def load_rules
        rules_dir = File.join(__dir__, "rules")
        require File.join(rules_dir, "base.rb")
        Dir[File.join(rules_dir, "*.rb")].sort.each do |file|
            next if File.basename(file) == "base.rb"
            require file
        end

        Rules.constants.each do |const|
            klass = Rules.const_get(const)
            next unless klass.is_a?(Class) && klass < Rules::Base
            @rules << klass.new
        end

        @rules.sort_by! { |r| Finding::SEVERITY_ORDER[r.severity] || 99 }
    end
end

require "yaml"

class Workflow
    attr_reader :filename, :raw, :raw_lines, :data

    def initialize(filename:, content:)
        @filename = filename
        @raw = content
        @raw_lines = content.lines
        @data = YAML.safe_load(content, permitted_classes: [Symbol]) || {}
    rescue YAML::SyntaxError => e
        @data = {}
        @parse_error = e.message
    end

    def parse_error? = !@parse_error.nil?

    def triggers
        @data["on"] || @data[true] || {}
    end

    def jobs
        @data["jobs"] || {}
    end

    def steps(job)
        job_hash = job.is_a?(String) ? jobs[job] : job
        return [] unless job_hash.is_a?(Hash)
        job_hash["steps"] || []
    end

    def permissions(scope: :workflow, job: nil)
        case scope
        when :workflow
            @data["permissions"]
        when :job
            j = job.is_a?(String) ? jobs[job] : job
            j&.dig("permissions")
        end
    end

    def env(scope: :workflow, step: nil)
        case scope
        when :workflow
            @data["env"] || {}
        when :step
            step&.dig("env") || {}
        end
    end

    def line_of(pattern)
        raw_lines.each_with_index do |line, i|
            return i + 1 if line.match?(pattern)
        end
        nil
    end

    def lines_of(pattern)
        results = []
        raw_lines.each_with_index do |line, i|
            results << (i + 1) if line.match?(pattern)
        end
        results
    end

    def line_content(num)
        raw_lines[num - 1]&.rstrip
    end

    def uses_actions
        results = []
        seen_lines = Hash.new(0)
        jobs.each do |_job_id, job_hash|
            steps(job_hash).each do |step|
                next unless step["uses"]
                all_lines = lines_of(/uses:\s*#{Regexp.escape(step["uses"])}/)
                idx = seen_lines[step["uses"]]
                line = all_lines[idx] || all_lines.last
                seen_lines[step["uses"]] += 1
                results << { uses: step["uses"], step: step, line: line }
            end
        end
        results
    end

    def run_blocks
        results = []
        all_run_lines = lines_of(/^\s+run:\s*[\|>]?\s*/)
        run_idx = 0
        jobs.each do |_job_id, job_hash|
            steps(job_hash).each do |step|
                next unless step["run"]
                line = all_run_lines[run_idx] || all_run_lines.last
                run_idx += 1
                results << { run: step["run"], step: step, env: step["env"] || {}, line: line }
            end
        end
        results
    end
end

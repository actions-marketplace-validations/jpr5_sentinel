require "net/http"
require "json"
require "uri"
require_relative "auto_fix"

module AiFix
    DEFAULT_MODEL = "claude-opus-4-20250514"

    def self.can_fix?(finding)
        !AutoFix.can_fix?(finding)
    end

    def self.apply(finding, raw_content, model: DEFAULT_MODEL, api_key: nil)
        api_key ||= ENV["ANTHROPIC_API_KEY"]
        return nil unless api_key

        prompt = build_prompt(finding, raw_content)
        response = call_claude(prompt, model: model, api_key: api_key)
        extract_yaml(response)
    end

    def self.build_prompt(finding, raw_content)
        <<~PROMPT
        You are a GitHub Actions security expert. Fix the following security finding in this workflow YAML.

        FINDING:
        - Rule: #{finding.rule}
        - Severity: #{finding.severity}
        - File: #{finding.file}
        - Line: #{finding.line}
        - Code: #{finding.code}
        - Issue: #{finding.message}
        - Suggested fix: #{finding.fix}

        WORKFLOW YAML:
        ```yaml
        #{raw_content}
        ```

        INSTRUCTIONS:
        - Fix ONLY the identified security finding
        - Preserve all existing functionality and workflow intent
        - Do not change anything unrelated to the finding
        - Preserve comments, formatting, and indentation style
        - Return ONLY the complete fixed YAML, no explanation
        - Do not wrap in markdown code fences
        PROMPT
    end

    def self.call_claude(prompt, model:, api_key:)
        uri = URI("https://api.anthropic.com/v1/messages")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 30
        http.read_timeout = 120

        body = {
            model: model,
            max_tokens: 8192,
            messages: [{ role: "user", content: prompt }]
        }

        req = Net::HTTP::Post.new(uri)
        req["Content-Type"] = "application/json"
        req["x-api-key"] = api_key
        req["anthropic-version"] = "2023-06-01"
        req.body = JSON.generate(body)

        resp = http.request(req)

        unless resp.code.to_i == 200
            $stderr.puts "Claude API error #{resp.code}: #{resp.body}"
            return nil
        end

        data = JSON.parse(resp.body)
        data.dig("content", 0, "text")
    end

    def self.extract_yaml(response)
        return nil unless response

        # Strip markdown fences if Claude included them despite instructions
        cleaned = response.strip
        cleaned = cleaned.sub(/\A```ya?ml\n?/, "").sub(/\n?```\z/, "")
        cleaned
    end
end

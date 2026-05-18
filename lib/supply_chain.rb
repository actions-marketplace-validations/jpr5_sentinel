require "net/http"
require "json"
require "uri"
require "time"

class SupplyChain
    def initialize(token: nil)
        @token = token || ENV["GITHUB_TOKEN"]
        @cache = {}
    end

    def analyze(workflows)
        actions = extract_actions(workflows)
        actions.map { |a| enrich(a) }
    end

    private

    def extract_actions(workflows)
        actions = {}
        workflows.each do |wf|
            wf.uses_actions.each do |action|
                uses = action[:uses]
                next if uses.nil? || uses.start_with?("./") || uses.start_with?("docker://")

                owner_action, ref = uses.split("@", 2)
                parts = owner_action.split("/")
                repo = "#{parts[0]}/#{parts[1]}"

                actions[repo] ||= {
                    repo: repo,
                    refs: [],
                    used_in: [],
                    owner: parts[0],
                    first_party: %w[actions github].include?(parts[0])
                }
                actions[repo][:refs] << ref unless actions[repo][:refs].include?(ref)
                actions[repo][:used_in] << { file: wf.filename, line: action[:line] }
            end
        end
        actions.values
    end

    def enrich(action)
        return action if action[:first_party]  # skip API calls for actions/*
        return action unless @token

        repo_data = fetch_repo(action[:repo])
        return action unless repo_data

        action[:stars] = repo_data["stargazers_count"]
        action[:archived] = repo_data["archived"]
        action[:last_push] = repo_data["pushed_at"]
        action[:owner_type] = repo_data.dig("owner", "type")  # User vs Organization
        action[:license] = repo_data.dig("license", "spdx_id")
        action[:description] = repo_data["description"]

        # Risk scoring
        action[:risk_score] = calculate_risk(action)
        action[:risk_factors] = identify_risks(action)

        action
    end

    def calculate_risk(action)
        score = 0
        score += 3 if (action[:stars] || 0) < 100
        score += 2 if (action[:stars] || 0) < 1000
        score += 3 if action[:archived]
        score += 2 if action[:owner_type] == "User"  # personal account, not org
        score += 1 if action[:refs]&.any? { |r| !r.match?(/[0-9a-f]{40}/) }  # not SHA-pinned

        # Stale check — no push in 6 months
        if action[:last_push]
            last = Time.parse(action[:last_push]) rescue nil
            score += 2 if last && (Time.now - last) > 180 * 86400
        end

        score
    end

    def identify_risks(action)
        risks = []
        risks << "Low stars (#{action[:stars]})" if (action[:stars] || 0) < 100
        risks << "Archived repository" if action[:archived]
        risks << "Personal account (not org)" if action[:owner_type] == "User"
        risks << "Not SHA-pinned" if action[:refs]&.any? { |r| !r.match?(/[0-9a-f]{40}/) }

        if action[:last_push]
            last = Time.parse(action[:last_push]) rescue nil
            risks << "Stale (no push in 6+ months)" if last && (Time.now - last) > 180 * 86400
        end

        risks
    end

    def fetch_repo(repo)
        @cache[repo] ||= begin
            encoded = repo.split("/").map { |p| URI.encode_www_form_component(p) }.join("/")
            uri = URI("https://api.github.com/repos/#{encoded}")
            req = Net::HTTP::Get.new(uri)
            req["Authorization"] = "Bearer #{@token}" if @token
            req["Accept"] = "application/vnd.github+json"

            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.open_timeout = 10
            http.read_timeout = 15

            resp = http.request(req)
            resp.code.to_i == 200 ? JSON.parse(resp.body) : nil
        rescue StandardError
            nil
        end
    end
end

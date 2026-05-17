require "net/http"
require "json"
require "uri"
require "base64"
require "yaml"

class GitHubClient
    API_BASE = "https://api.github.com"

    def initialize(token: nil)
        @token = token || ENV["GITHUB_TOKEN"]
    end

    def fetch_workflows(repo)
        workflows = []
        files = api_get("/repos/#{repo}/contents/.github/workflows")
        return workflows unless files.is_a?(Array)

        files.each do |f|
            next unless f["name"].end_with?(".yml", ".yaml")
            content = fetch_file_content(repo, f["path"])
            next unless content
            workflows << { filename: f["name"], content: content }
        end

        workflows
    end

    def fetch_file_content(repo, path)
        data = api_get("/repos/#{repo}/contents/#{path}")
        return nil unless data.is_a?(Hash) && data["content"]
        Base64.decode64(data["content"])
    end

    def fetch_repos(org)
        repos = []
        page = 1
        loop do
            batch = api_get("/orgs/#{org}/repos?per_page=100&page=#{page}&type=all")
            break unless batch.is_a?(Array) && !batch.empty?
            batch.each do |r|
                next if r["archived"]
                repos << r["full_name"]
            end
            page += 1
            break if batch.length < 100
        end
        repos.sort
    end

    def file_exists?(repo, path)
        !api_get("/repos/#{repo}/contents/#{path}").nil?
    rescue StandardError
        false
    end

    def fetch_dependabot_config(repo)
        content = fetch_file_content(repo, ".github/dependabot.yml")
        content ||= fetch_file_content(repo, ".github/dependabot.yaml")
        return nil unless content
        begin
            YAML.safe_load(content)
        rescue StandardError => e
            nil
        end
    end

    private

    def api_get(path)
        uri = URI("#{API_BASE}#{path}")
        req = Net::HTTP::Get.new(uri)
        req["Accept"] = "application/vnd.github+json"
        req["Authorization"] = "Bearer #{@token}" if @token
        req["X-GitHub-Api-Version"] = "2022-11-28"

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 30

        resp = http.request(req)

        case resp.code.to_i
        when 200
            JSON.parse(resp.body)
        when 404
            nil
        when 403
            $stderr.puts "Rate limited or forbidden: #{path}"
            nil
        else
            $stderr.puts "API error #{resp.code}: #{path}"
            nil
        end
    end
end

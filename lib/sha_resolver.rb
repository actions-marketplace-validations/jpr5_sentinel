require "net/http"
require "json"
require "uri"

class ShaResolver
    API_BASE = "https://api.github.com"

    def initialize(token: nil)
        @token = token || ENV["GITHUB_TOKEN"]
        @cache = {}
    end

    def resolve(owner_action, tag)
        repo = extract_repo(owner_action)
        key = "#{repo}@#{tag}"
        @cache[key] ||= fetch_sha(repo, tag)
    end

    private

    def extract_repo(owner_action)
        parts = owner_action.split("/")
        "#{parts[0]}/#{parts[1]}"
    end

    def fetch_sha(repo, tag)
        encoded_repo = repo.split("/").map { |p| URI.encode_www_form_component(p) }.join("/")
        encoded_tag = URI.encode_www_form_component(tag)
        uri = URI("#{API_BASE}/repos/#{encoded_repo}/commits/#{encoded_tag}")
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
            data = JSON.parse(resp.body)
            data["sha"]
        when 404
            $stderr.puts "ShaResolver: tag '#{tag}' not found for #{repo}"
            nil
        when 403
            $stderr.puts "ShaResolver: rate limited or forbidden for #{repo}"
            nil
        else
            $stderr.puts "ShaResolver: API error #{resp.code} for #{repo}@#{tag}"
            nil
        end
    rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED => e
        $stderr.puts "SHA resolve failed for #{repo}@#{tag}: #{e.message}"
        nil
    end
end

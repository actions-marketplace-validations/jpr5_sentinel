require "net/http"
require "json"
require "uri"

module Bot
    class Search
        API_BASE = "https://api.github.com"
        MAX_PAGES = 10
        PER_PAGE = 30
        # GitHub Code Search rate limit: 10 requests/minute
        SEARCH_DELAY = 7

        def initialize(token:)
            @token = token
        end

        def find_candidates(query_config)
            repos = {}
            page = 1

            loop do
                break if page > MAX_PAGES

                results = search_code(query_config[:query], page: page)
                break unless results && results["items"]
                break if results["items"].empty?

                results["items"].each do |item|
                    repo = item["repository"]
                    full_name = repo["full_name"]
                    next if repos.key?(full_name)

                    repos[full_name] = { full_name: full_name, html_url: repo["html_url"] }
                end

                break if results["items"].length < PER_PAGE
                page += 1
                sleep(SEARCH_DELAY)
            end

            # Now filter by star count (requires individual repo lookups)
            candidates = []
            repos.each_value do |repo|
                repo_data = fetch_repo(repo[:full_name])
                next unless repo_data
                next if repo_data["archived"]

                stars = repo_data["stargazers_count"] || 0
                next if stars < Config::MIN_STARS

                candidates << { full_name: repo[:full_name], stars: stars }
                sleep(1) # gentle pacing for repo lookups
            end

            candidates.sort_by { |c| -c[:stars] }
        end

        private

        def search_code(query, page: 1)
            path = "/search/code?q=#{URI.encode_www_form_component(query)}&per_page=#{PER_PAGE}&page=#{page}"
            api_get(path)
        end

        def fetch_repo(full_name)
            api_get("/repos/#{full_name}")
        end

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
            when 403
                $stderr.puts "Rate limited: #{path}"
                nil
            when 422
                $stderr.puts "Validation failed (bad query?): #{path}"
                nil
            else
                $stderr.puts "API error #{resp.code}: #{path}"
                nil
            end
        end
    end
end

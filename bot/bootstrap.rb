require "net/http"
require "json"
require "uri"

module Bot
    class Bootstrap
        API_BASE = "https://api.github.com"

        KNOWN_ORGS = %w[CopilotKit ag-ui-protocol].freeze

        # GitHub Search rate limit: 30 requests/minute for authenticated users
        SEARCH_DELAY = 3

        def initialize(token:, state:)
            @token = token
            @state = state
        end

        def run(orgs: KNOWN_ORGS)
            summary = { found: 0, new: 0, already_tracked: 0, errors: 0 }
            discovered = []

            $stderr.puts "Bootstrapping PR tracker..."

            # 1. Global search for all Sentinel bot PRs by author (no org filter)
            $stderr.puts "  Searching globally for Sentinel PRs..."
            global_prs = search_global_for_sentinel_prs
            if global_prs.nil?
                summary[:errors] += 1
            else
                discovered.concat(global_prs)
            end

            # 2. Search each org for adoption PRs (these have different titles)
            orgs.each do |org|
                $stderr.puts "  Searching #{org} org for adoption PRs..."
                prs = search_org_for_adoption_prs(org)
                if prs.nil?
                    summary[:errors] += 1
                else
                    discovered.concat(prs)
                end
            end

            # 2. Check repos already in state that aren't in known orgs
            state_repos = repos_from_state(orgs)
            if state_repos.any?
                $stderr.puts "  Checking #{state_repos.length} repos in state..."
                state_repos.each do |repo|
                    prs = find_sentinel_prs_for_repo(repo)
                    if prs.nil?
                        summary[:errors] += 1
                    else
                        discovered.concat(prs)
                    end
                end
            end

            # 3. Deduplicate by repo+number
            discovered.uniq! { |pr| "#{pr[:repo]}##{pr[:number]}" }

            $stderr.puts "Found #{discovered.length} Sentinel PRs:"

            # 4. Record each discovered PR
            discovered.each do |pr|
                if already_tracked?(pr[:repo], pr[:number])
                    summary[:already_tracked] += 1
                    $stderr.puts "  #{pr[:repo]} ##{pr[:number]} — #{pr[:status]} (already tracked)"
                else
                    record_discovered_pr(pr)
                    summary[:new] += 1
                    $stderr.puts "  #{pr[:repo]} ##{pr[:number]} — #{pr[:status]} (NEW)"
                end
                summary[:found] += 1
            end

            $stderr.puts "Bootstrap complete: #{summary[:found]} found, #{summary[:new]} new, #{summary[:already_tracked]} already tracked"

            summary
        end

        private

        # Search an org for PRs that look like Sentinel PRs.
        # Uses two search strategies:
        #   1. PRs with "Security: Fix" + "finding" + "Sentinel" (the bot's fix-PR pattern)
        #   2. PRs with "Add Sentinel CI/CD" in the title (the scan-addition pattern)
        # Results are post-filtered in parse_search_result to validate Sentinel origin.
        # Returns nil if all searches fail (API errors), empty array if no results.
        def search_global_for_sentinel_prs
            prs = []
            query = 'is:pr author:jpr5 "Security: Fix" "finding" "GitHub Actions workflows"'
            results = search_issues(query)
            return nil unless results

            results.each do |item|
                pr = parse_search_result(item)
                prs << pr if pr
            end

            prs
        end

        def search_org_for_adoption_prs(org)
            prs = []
            query = "is:pr \"Add Sentinel CI/CD\" org:#{org}"
            results = search_issues(query)
            return nil unless results

            results.each do |item|
                pr = parse_search_result(item)
                prs << pr if pr
            end

            prs
        end

        # For repos already in state, check the pulls API directly
        def find_sentinel_prs_for_repo(repo)
            prs = []

            data = api_get("/repos/#{repo}/pulls?state=all&per_page=100")
            return nil unless data.is_a?(Array)

            data.each do |pr_data|
                head_ref = pr_data.dig("head", "ref") || ""
                next unless head_ref.start_with?("sentinel/")

                prs << parse_pulls_result(repo, pr_data)
            end

            prs
        end

        # Paginate through the search API.
        # Returns nil if the first API call fails, otherwise an array of items.
        def search_issues(query)
            all_items = []
            page = 1
            first_call = true

            loop do
                encoded = URI.encode_www_form_component(query)
                path = "/search/issues?q=#{encoded}&per_page=100&page=#{page}"
                data = api_get(path)

                unless data.is_a?(Hash)
                    return nil if first_call
                    break
                end
                first_call = false

                items = data["items"] || []
                break if items.empty?

                all_items.concat(items)

                # Stop if we've gotten all results
                total = data["total_count"] || 0
                break if all_items.length >= total
                break if items.length < 100

                page += 1
                sleep(SEARCH_DELAY)
            end

            all_items
        end

        def parse_search_result(item)
            # Search API returns issues, so we need to extract repo from the URL
            html_url = item["html_url"] || ""
            return nil unless html_url =~ %r{github\.com/([^/]+/[^/]+)/pull/(\d+)}

            # Post-filter: validate this actually looks like a Sentinel PR
            body = item["body"] || ""
            title = item["title"] || ""
            head_ref = item.dig("pull_request", "head", "ref") || ""

            is_sentinel = head_ref.start_with?("sentinel/") ||
                          body.include?("sentinel.copilotkit.dev") ||
                          body.include?("sentinel-ci-scanner") ||
                          body.include?("Sentinel Bot") ||
                          title.match?(/\ASecurity: Fix \d+ finding/) ||
                          title.match?(/\AAdd Sentinel CI\/CD/)

            return nil unless is_sentinel

            repo = $1
            number = $2.to_i
            state = item["state"]
            # Search API doesn't directly tell us if merged — check pull_request.merged_at
            merged_at = item.dig("pull_request", "merged_at")

            status = if merged_at
                "merged"
            elsif state == "closed"
                "closed"
            else
                "open"
            end

            {
                repo: repo,
                number: number,
                url: html_url,
                status: status,
                created_at: item["created_at"],
                updated_at: item["updated_at"],
            }
        end

        def parse_pulls_result(repo, pr_data)
            number = pr_data["number"]
            merged = pr_data["merged_at"] || pr_data["merged"]

            status = if merged
                "merged"
            elsif pr_data["state"] == "closed"
                "closed"
            else
                "open"
            end

            {
                repo: repo,
                number: number,
                url: pr_data["html_url"],
                status: status,
                created_at: pr_data["created_at"],
                updated_at: pr_data["updated_at"],
            }
        end

        def repos_from_state(exclude_orgs)
            exclude_prefixes = exclude_orgs.map { |org| "#{org}/" }
            tracked = @state.all_tracked_prs.map { |e| e[:repo] }
            # Also include repos in state that have scans but no PRs
            # (state data includes all repos, all_tracked_prs only returns those with PRs)
            all_repos = tracked

            # Get all repo names from state by checking what record_scan has stored
            # We need to look at the state's internal data — use the repos that have entries
            all_repos.uniq.reject { |repo| exclude_prefixes.any? { |p| repo.start_with?(p) } }
        end

        def already_tracked?(repo, number)
            @state.all_tracked_prs.any? { |e| e[:repo] == repo && e[:pr]["number"] == number }
        end

        def record_discovered_pr(pr)
            @state.record_pr(pr[:repo], pr[:url], "multiple", pr[:number])
            @state.update_pr_status(pr[:repo], pr[:number], pr[:status],
                created_at: pr[:created_at],
                updated_at: pr[:updated_at])
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
            when 404
                nil
            when 403
                $stderr.puts "Rate limited or forbidden: #{path}"
                nil
            when 422
                $stderr.puts "Validation error: #{resp.body}"
                nil
            else
                $stderr.puts "API error #{resp.code}: #{path}"
                nil
            end
        rescue Net::OpenTimeout, Net::ReadTimeout, SocketError, Errno::ECONNREFUSED, OpenSSL::SSL::SSLError => e
            $stderr.puts "Network error for #{path}: #{e.message}"
            nil
        end
    end
end

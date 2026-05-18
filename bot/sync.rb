require "net/http"
require "json"
require "uri"
require "time"

module Bot
    class Sync
        API_BASE = "https://api.github.com"

        TERMINAL_STATUSES = %w[merged].freeze

        def initialize(token:, state:)
            @token = token
            @state = state
        end

        def sync_all(force: false)
            prs = force ? @state.all_tracked_prs : @state.non_terminal_prs
            results = { synced: 0, updated: 0, errors: 0 }

            $stderr.puts "Syncing #{prs.length} PRs..."

            prs.each do |entry|
                repo = entry[:repo]
                pr = entry[:pr]
                old_status = pr["status"]

                new_status = sync_pr(repo, pr)

                if new_status.nil?
                    results[:errors] += 1
                    next
                end

                results[:synced] += 1

                if new_status != old_status
                    results[:updated] += 1
                    note = pr["_sync_note"]
                    $stderr.puts "  #{repo} ##{pr["number"]}: #{old_status} → #{new_status}"
                else
                    $stderr.puts "  #{repo} ##{pr["number"]}: #{old_status} → #{new_status} (no change)"
                end
            end

            $stderr.puts "Sync complete: #{results[:synced]} synced, #{results[:updated]} updated, #{results[:errors]} errors"
            results
        end

        def sync_pr(repo, pr_entry)
            number = pr_entry["number"]
            return nil unless number

            owner, name = repo.split("/")
            return nil unless owner && name

            # 1. Get PR data
            pr_data = api_get("/repos/#{owner}/#{name}/pulls/#{number}")
            return nil unless pr_data

            # Derive status
            status, note = derive_status(owner, name, pr_data)

            # Update state
            @state.update_pr_status(repo, number, status, note: note)

            # Stash note for sync_all reporting (transient, not persisted)
            pr_entry["_sync_note"] = note

            status
        end

        private

        def derive_status(owner, name, pr_data)
            number = pr_data["number"]

            # Merged check
            if pr_data["merged"] == true
                return ["merged", nil]
            end

            # Closed (not merged)
            if pr_data["state"] == "closed"
                return ["closed", nil]
            end

            # PR is open — check for blockers
            blockers = []

            # Check reviews for changes_requested
            review_blockers = check_reviews(owner, name, number)
            blockers.concat(review_blockers)

            # Check CI status via check-runs
            head_sha = pr_data.dig("head", "sha")
            if head_sha
                ci_blockers = check_ci(owner, name, head_sha)
                blockers.concat(ci_blockers)
            end

            if blockers.any?
                note = blockers.join("; ")
                return ["blocked", note]
            end

            ["open", nil]
        end

        def check_reviews(owner, name, number)
            blockers = []

            reviews = api_get("/repos/#{owner}/#{name}/pulls/#{number}/reviews?per_page=100")
            return blockers unless reviews.is_a?(Array)

            # Build per-reviewer state: only the latest review per user matters
            latest_by_user = {}
            reviews.each do |review|
                user = review.dig("user", "login")
                state = review["state"]
                next unless user && state

                # Only state-changing reviews matter; COMMENTED/PENDING don't clear prior decisions
                next if state == "COMMENTED" || state == "PENDING"

                # Track the latest review by each user (reviews come in chronological order)
                latest_by_user[user] = state
            end

            # Check for any reviewer whose latest review is CHANGES_REQUESTED
            latest_by_user.each do |user, state|
                if state == "CHANGES_REQUESTED"
                    blockers << "Changes requested by @#{user}"
                end
            end

            blockers
        end

        def check_ci(owner, name, sha)
            blockers = []

            data = api_get("/repos/#{owner}/#{name}/commits/#{sha}/check-runs?per_page=100")
            return blockers unless data.is_a?(Hash)

            check_runs = data["check_runs"] || []

            # First pass: CLA/DCO checks (special note)
            cla_failing = false
            check_runs.each do |cr|
                check_name = cr["name"] || ""
                conclusion = cr["conclusion"]

                if conclusion == "failure" && check_name.downcase =~ /cla|dco/
                    blockers << "CLA/DCO check failing"
                    cla_failing = true
                    break  # Only report CLA/DCO once
                end
            end

            # Second pass: other failing checks
            check_runs.each do |cr|
                check_name = cr["name"] || ""
                conclusion = cr["conclusion"]

                next unless conclusion == "failure"
                next if check_name.downcase =~ /cla|dco/  # Already handled above

                blockers << "CI failing: #{check_name}"
            end

            blockers
        end

        def api_get(path)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Get.new(uri)
            set_headers(req)
            execute(uri, req)
        end

        def set_headers(req)
            req["Accept"] = "application/vnd.github+json"
            req["Authorization"] = "Bearer #{@token}" if @token
            req["X-GitHub-Api-Version"] = "2022-11-28"
        end

        def execute(uri, req)
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
                $stderr.puts "Rate limited or forbidden: #{req.path}"
                nil
            else
                $stderr.puts "API error #{resp.code}: #{req.path}"
                nil
            end
        end
    end
end

require "json"
require "time"
require "fileutils"

module Bot
    class State
        def initialize(path = Config::STATE_FILE)
            @path = resolve_state_path(path)
            @data = with_lock {
                if File.exist?(path)
                    JSON.parse(File.read(path))
                else
                    { "repos" => {}, "opt_outs" => [] }
                end
            }

            # Auto-restore from gist backup if state is empty and backup is configured
            if @data["repos"].empty? && ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
                auto_restore_from_backup
            end

            migrate!
        end

        def save
            prune
            with_lock do
                tmp = "#{@path}.tmp"
                File.write(tmp, JSON.pretty_generate(@data))
                File.rename(tmp, @path)
            end
        end

        def already_processed?(repo_name, rule)
            repo_data = @data["repos"][repo_name]
            return false unless repo_data

            # Consider processed if we opened a PR for this rule
            prs = repo_data["prs"] || []
            prs.any? { |pr| pr["rule"] == rule }
        end

        def record_scan(repo_name, findings)
            @data["repos"][repo_name] ||= { "scans" => [], "prs" => [] }
            @data["repos"][repo_name]["scans"] << {
                "timestamp" => Time.now.utc.iso8601,
                "finding_count" => findings.length,
                "rules" => findings.map { |f| f.is_a?(Hash) ? f[:rule] : f.rule }.uniq,
            }
            @data["repos"][repo_name]["last_scanned_at"] = Time.now.utc.iso8601
            @data["repos"][repo_name]["status"] ||= "scanned"
        end

        def record_pr(repo_name, pr_url, rule, number, type: nil)
            @data["repos"][repo_name] ||= { "scans" => [], "prs" => [] }
            entry = {
                "url" => pr_url,
                "number" => number,
                "rule" => rule,
                "status" => "open",
                "note" => nil,
                "created_at" => Time.now.utc.iso8601,
                "last_updated_at" => Time.now.utc.iso8601,
                "synced_at" => nil,
            }
            entry["type"] = type if type
            @data["repos"][repo_name]["prs"] << entry
        end

        def update_pr_status(repo_name, number, status, note: nil, created_at: nil, updated_at: nil)
            repo_data = @data["repos"][repo_name]
            return unless repo_data

            pr = repo_data["prs"]&.find { |p| p["number"] == number }
            return unless pr

            pr["status"] = status
            pr["note"] = note unless note.nil?
            pr["created_at"] = created_at if created_at
            pr["last_updated_at"] = updated_at || Time.now.utc.iso8601
            pr["synced_at"] = Time.now.utc.iso8601
        end

        def prs_by_status(status)
            all_tracked_entries.select { |e| e[:pr]["status"] == status }
        end

        def all_tracked_entries
            results = []
            @data["repos"].each do |repo_name, repo_data|
                (repo_data["prs"] || []).each do |pr|
                    results << { repo: repo_name, pr: pr }
                end
            end
            results
        end

        def all_tracked_prs
            all_tracked_entries.select { |e| (e[:pr]["type"] || "pr") == "pr" }
        end

        def all_tracked_issues
            all_tracked_entries.select { |e| e[:pr]["type"] == "issue" }
        end

        def non_terminal_prs
            all_tracked_entries.reject { |e| e[:pr]["status"] == "merged" }
        end

        def record_opt_out(repo_name)
            @data["opt_outs"] << repo_name unless @data["opt_outs"].include?(repo_name)
        end

        def opted_out?(repo_name)
            @data["opt_outs"].include?(repo_name)
        end

        def record_token(token, repo, action)
            @data["tokens"] ||= {}
            @data["tokens"][token] = {
                "repo" => repo,
                "action" => action,
                "created_at" => Time.now.utc.iso8601,
            }
        end

        def valid_token?(token, repo, action)
            entry = @data.dig("tokens", token)
            return false unless entry
            return false unless entry["repo"] == repo && entry["action"] == action
            # 30-day expiry
            created = Time.parse(entry["created_at"]) rescue nil
            return false if created && (Time.now.utc - created) > 30 * 86400
            true
        end

        def consume_token(token)
            @data["tokens"]&.delete(token)
        end

        def prs_opened_today
            today = Time.now.utc.strftime("%Y-%m-%d")
            count = 0
            @data["repos"].each do |_, repo_data|
                (repo_data["prs"] || []).each do |pr|
                    timestamp = pr["created_at"] || pr["timestamp"]
                    count += 1 if timestamp&.start_with?(today)
                end
            end
            count
        end

        def rate_limit_reached?
            prs_opened_today >= Config::MAX_PRS_PER_DAY
        end

        def dashboard_excluded_statuses
            @data.dig("dashboard_preferences", "excluded_statuses") || []
        end

        def set_dashboard_excluded_statuses(statuses)
            @data["dashboard_preferences"] ||= {}
            @data["dashboard_preferences"]["excluded_statuses"] = statuses
        end

        def summary
            entries = all_tracked_entries
            {
                total_repos: @data["repos"].length,
                total_prs: entries.count { |e| (e[:pr]["type"] || "pr") == "pr" },
                total_issues: entries.count { |e| e[:pr]["type"] == "issue" },
                prs_today: prs_opened_today,
                opt_outs: @data["opt_outs"].length,
            }
        end

        private

        def auto_restore_from_backup
            require_relative "backup"
            $stderr.puts "State is empty — restoring from gist backup..."
            queue_path = File.join(File.dirname(@path), "queue.json")
            backup = Backup.new(token: ENV["GITHUB_TOKEN"], state_path: @path, queue_path: queue_path)
            with_lock { backup.restore }
            # Re-read the restored file
            if File.exist?(@path)
                restored = JSON.parse(File.read(@path))
                if restored["repos"] && !restored["repos"].empty?
                    @data = restored
                    $stderr.puts "Restored #{@data["repos"].length} repos from backup"
                end
            end
        rescue => e
            $stderr.puts "Auto-restore failed (non-fatal): #{e.message}"
        end

        def resolve_state_path(path)
            dir = File.dirname(path)
            FileUtils.mkdir_p(dir)
            path
        rescue Errno::EROFS, Errno::EACCES, Errno::EPERM
            fallback = File.join(Dir.pwd, "bot", "state.json")
            $stderr.puts "Cannot write to #{dir}, falling back to #{fallback}"
            FileUtils.mkdir_p(File.dirname(fallback))
            fallback
        end

        def with_lock(&block)
            lockfile = "#{@path}.lock"
            FileUtils.mkdir_p(File.dirname(lockfile))
            File.open(lockfile, File::CREAT | File::RDWR) do |f|
                f.flock(File::LOCK_EX)
                block.call
            end
        end

        def migrate!
            # Remove top-level prs array (old dual-storage format)
            @data.delete("prs")

            # Backfill new fields on existing per-repo PR entries
            @data["repos"].each do |_, repo_data|
                (repo_data["prs"] || []).each do |pr|
                    # Extract number from URL if missing
                    if pr["number"].nil? && pr["url"]
                        if pr["url"] =~ /\/pull\/(\d+)$/
                            pr["number"] = $1.to_i
                        end
                    end

                    # Backfill status
                    pr["status"] ||= "open"

                    # Backfill synced_at
                    pr["synced_at"] = nil unless pr.key?("synced_at")

                    # Backfill created_at from timestamp
                    pr["created_at"] ||= pr["timestamp"]

                    # Backfill last_updated_at from timestamp
                    pr["last_updated_at"] ||= pr["timestamp"]

                    # Backfill note
                    pr["note"] = nil unless pr.key?("note")
                end
            end
        end

        def prune(max_age_days: 90)
            cutoff = (Time.now.utc - max_age_days * 86400).iso8601
            @data["repos"].delete_if { |_, v|
                v["last_scanned_at"] && v["last_scanned_at"] < cutoff && v["status"] == "scanned"
            }
            prune_tokens
        end

        def prune_tokens(max_age_days: 30)
            cutoff = (Time.now.utc - max_age_days * 86400).iso8601
            @data["tokens"]&.delete_if { |_, v| v["created_at"] && v["created_at"] < cutoff }
        end
    end
end

require "json"
require "time"

module Bot
    class State
        def initialize(path = Config::STATE_FILE)
            @path = path
            @data = if File.exist?(path)
                JSON.parse(File.read(path))
            else
                { "repos" => {}, "prs" => [], "opt_outs" => [] }
            end
        end

        def save
            prune
            tmp = "#{@path}.tmp"
            File.open(@path, File::CREAT | File::RDWR) do |lock|
                lock.flock(File::LOCK_EX)
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

        def record_pr(repo_name, pr_url, rule)
            @data["repos"][repo_name] ||= { "scans" => [], "prs" => [] }
            @data["repos"][repo_name]["prs"] << {
                "url" => pr_url,
                "rule" => rule,
                "timestamp" => Time.now.utc.iso8601,
            }

            @data["prs"] << {
                "repo" => repo_name,
                "url" => pr_url,
                "rule" => rule,
                "timestamp" => Time.now.utc.iso8601,
            }
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
            # 7-day expiry
            created = Time.parse(entry["created_at"]) rescue nil
            return false if created && (Time.now.utc - created) > 7 * 86400
            true
        end

        def consume_token(token)
            @data["tokens"]&.delete(token)
        end

        def prs_opened_today
            today = Time.now.utc.strftime("%Y-%m-%d")
            @data["prs"].count { |pr| pr["timestamp"]&.start_with?(today) }
        end

        def rate_limit_reached?
            prs_opened_today >= Config::MAX_PRS_PER_DAY
        end

        def summary
            {
                total_repos: @data["repos"].length,
                total_prs: @data["prs"].length,
                prs_today: prs_opened_today,
                opt_outs: @data["opt_outs"].length,
            }
        end

        private

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

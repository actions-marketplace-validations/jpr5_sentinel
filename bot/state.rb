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
            File.write(@path, JSON.pretty_generate(@data))
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
                "timestamp" => Time.now.iso8601,
                "finding_count" => findings.length,
                "rules" => findings.map { |f| f.is_a?(Hash) ? f[:rule] : f.rule }.uniq,
            }
        end

        def record_pr(repo_name, pr_url, rule)
            @data["repos"][repo_name] ||= { "scans" => [], "prs" => [] }
            @data["repos"][repo_name]["prs"] << {
                "url" => pr_url,
                "rule" => rule,
                "timestamp" => Time.now.iso8601,
            }

            @data["prs"] << {
                "repo" => repo_name,
                "url" => pr_url,
                "rule" => rule,
                "timestamp" => Time.now.iso8601,
            }
        end

        def record_opt_out(repo_name)
            @data["opt_outs"] << repo_name unless @data["opt_outs"].include?(repo_name)
        end

        def opted_out?(repo_name)
            @data["opt_outs"].include?(repo_name)
        end

        def prs_opened_today
            today = Time.now.strftime("%Y-%m-%d")
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
    end
end

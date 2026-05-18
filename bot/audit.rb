module Bot
    class Audit
        def initialize(path = nil)
            @path = path || ENV["SENTINEL_AUDIT_LOG"] || "bot/audit.log"
        end

        def log(action, repo: nil, details: nil)
            entry = "#{Time.now.utc.iso8601} #{action}"
            entry += " repo=#{repo}" if repo
            entry += " #{details}" if details

            File.open(@path, "a") do |f|
                f.flock(File::LOCK_EX)
                f.puts entry
            end

            $stderr.puts "[AUDIT] #{entry}"
        end

        def scan(repo, findings_count)
            log("SCAN", repo: repo, details: "findings=#{findings_count}")
        end

        def skip(repo, reason)
            log("SKIP", repo: repo, details: "reason=#{reason}")
        end

        def fix(repo, rule, file)
            log("FIX", repo: repo, details: "rule=#{rule} file=#{file}")
        end

        def pr_created(repo, url)
            log("PR_CREATED", repo: repo, details: "url=#{url}")
        end

        def pr_failed(repo, reason)
            log("PR_FAILED", repo: repo, details: "reason=#{reason}")
        end

        def opt_out(repo)
            log("OPT_OUT", repo: repo)
        end

        def adopt(repo)
            log("ADOPT", repo: repo)
        end

        def error(repo, message)
            log("ERROR", repo: repo, details: "msg=#{message}")
        end

        def run_start(pattern, dry_run, limit)
            log("RUN_START", details: "pattern=#{pattern} dry_run=#{dry_run} limit=#{limit || 'none'}")
        end

        def run_end(summary)
            log("RUN_END", details: "scanned=#{summary[:scanned]} findings=#{summary[:findings]} prs=#{summary[:prs_opened]} skipped=#{summary[:skipped]} errors=#{summary[:errors]}")
        end
    end
end

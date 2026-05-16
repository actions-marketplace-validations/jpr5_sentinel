require "net/http"
require "json"
require "uri"
require "base64"

module Bot
    class PrWriter
        API_BASE = "https://api.github.com"

        def initialize(token:)
            @token = token
        end

        def create_pr(repo:, branch:, title:, body:, files:)
            owner, name = repo.split("/")

            # 1. Fork the repo
            fork = fork_repo(repo)
            return nil unless fork

            fork_full_name = fork["full_name"]
            fork_owner = fork["owner"]["login"]

            # Wait for fork to become available
            return nil unless wait_for_fork(fork_owner, repo.split("/").last)

            # 2. Get default branch ref (to base our branch on)
            default_branch = fork["parent"]&.dig("default_branch") || "main"
            ref_data = api_get("/repos/#{fork_full_name}/git/ref/heads/#{default_branch}")
            return nil unless ref_data

            base_sha = ref_data["object"]["sha"]

            # 3. Create branch on fork
            branch_created = create_branch(fork_full_name, branch, base_sha)
            return nil unless branch_created

            # 4. Commit fixed files to the branch
            files.each do |file_path, content|
                committed = commit_file(
                    repo: fork_full_name,
                    branch: branch,
                    path: file_path,
                    content: content,
                    message: "fix: #{title}"
                )
                return nil unless committed
            end

            # 5. Open cross-fork PR
            pr = open_pull_request(
                target_repo: repo,
                head: "#{fork_owner}:#{branch}",
                title: title,
                body: body
            )

            pr
        end

        private

        def wait_for_fork(fork_owner, repo_name)
            attempts = 0
            loop do
                attempts += 1
                result = api_get("/repos/#{fork_owner}/#{repo_name}")
                return true if result
                break if attempts >= 10
                sleep([2 ** attempts, 30].min)
            end
            false
        end

        def fork_repo(repo)
            resp = api_post("/repos/#{repo}/forks", {})
            return resp if resp

            $stderr.puts "Failed to fork #{repo}"
            nil
        end

        def create_branch(repo, branch, sha)
            resp = api_post("/repos/#{repo}/git/refs", {
                ref: "refs/heads/#{branch}",
                sha: sha,
            })

            if resp.nil?
                # Branch might already exist; try to update it
                resp = api_patch("/repos/#{repo}/git/refs/heads/#{branch}", {
                    sha: sha,
                    force: true,
                })
            end

            resp
        end

        def commit_file(repo:, branch:, path:, content:, message:)
            # Check if file already exists (to get its SHA for updates)
            existing = api_get("/repos/#{repo}/contents/#{path}?ref=#{branch}")
            file_sha = existing&.dig("sha")

            payload = {
                message: message,
                content: Base64.strict_encode64(content),
                branch: branch,
            }
            payload[:sha] = file_sha if file_sha

            api_put("/repos/#{repo}/contents/#{path}", payload)
        end

        def open_pull_request(target_repo:, head:, title:, body:)
            api_post("/repos/#{target_repo}/pulls", {
                title: title,
                body: body,
                head: head,
                base: default_branch_for(target_repo),
            })
        end

        def default_branch_for(repo)
            data = api_get("/repos/#{repo}")
            data&.dig("default_branch") || "main"
        end

        def api_get(path)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Get.new(uri)
            set_headers(req)
            execute(uri, req)
        end

        def api_post(path, body)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Post.new(uri)
            set_headers(req)
            req.body = JSON.generate(body)
            execute(uri, req)
        end

        def api_put(path, body)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Put.new(uri)
            set_headers(req)
            req.body = JSON.generate(body)
            execute(uri, req)
        end

        def api_patch(path, body)
            uri = URI("#{API_BASE}#{path}")
            req = Net::HTTP::Patch.new(uri)
            set_headers(req)
            req.body = JSON.generate(body)
            execute(uri, req)
        end

        def set_headers(req)
            req["Accept"] = "application/vnd.github+json"
            req["Authorization"] = "Bearer #{@token}" if @token
            req["X-GitHub-Api-Version"] = "2022-11-28"
            req["Content-Type"] = "application/json"
        end

        def execute(uri, req)
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.open_timeout = 10
            http.read_timeout = 30

            resp = http.request(req)

            case resp.code.to_i
            when 200, 201, 202
                JSON.parse(resp.body)
            when 404
                nil
            when 403
                $stderr.puts "Rate limited or forbidden: #{req.path}"
                nil
            when 422
                $stderr.puts "Validation error: #{resp.body}"
                nil
            else
                $stderr.puts "API error #{resp.code}: #{req.path}"
                nil
            end
        end
    end
end

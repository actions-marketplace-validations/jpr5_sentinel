require "net/http"
require "json"
require "uri"
require "time"
require "fileutils"

module Bot
    class Backup
        API_BASE = "https://api.github.com"
        STATE_GIST_FILENAME = "sentinel-state-backup.json"
        QUEUE_GIST_FILENAME = "sentinel-queue-backup.json"

        # Keep old constant for backward compatibility
        GIST_FILENAME = STATE_GIST_FILENAME

        def initialize(token:, state_path: Config::STATE_FILE, queue_path: nil)
            @token = token
            @state_path = state_path
            @queue_path = queue_path || File.join(File.dirname(state_path), "queue.json")
            @gist_id = ENV["SENTINEL_BACKUP_GIST_ID"]
        end

        def save
            files = {}

            if File.exist?(@state_path)
                files[STATE_GIST_FILENAME] = { "content" => File.read(@state_path) }
            else
                $stderr.puts "Backup: state file not found at #{@state_path}"
            end

            if File.exist?(@queue_path)
                files[QUEUE_GIST_FILENAME] = { "content" => File.read(@queue_path) }
            end

            if files.empty?
                $stderr.puts "Backup: no files to back up"
                return false
            end

            description = "Sentinel bot state backup — #{Time.now.utc.iso8601}"

            if @gist_id
                result = api_patch("/gists/#{@gist_id}", {
                    description: description,
                    files: files,
                })
            else
                result = api_post("/gists", {
                    description: description,
                    public: false,
                    files: files,
                })

                if result
                    @gist_id = result["id"]
                    $stderr.puts "Backup: created gist #{result["id"]}"
                    $stderr.puts "  Set SENTINEL_BACKUP_GIST_ID=#{result["id"]} to update this gist in future runs"
                end
            end

            if result
                $stderr.puts "Backup: saved to gist (#{files.keys.join(", ")})"
                true
            else
                $stderr.puts "Backup: failed to save"
                false
            end
        rescue => e
            $stderr.puts "Backup: error saving: #{e.message}"
            false
        end

        def restore
            unless @gist_id
                $stderr.puts "Backup: SENTINEL_BACKUP_GIST_ID not set, cannot restore"
                return false
            end

            data = api_get("/gists/#{@gist_id}")
            unless data
                $stderr.puts "Backup: failed to fetch gist #{@gist_id}"
                return false
            end

            restored = []

            state_content = data.dig("files", STATE_GIST_FILENAME, "content")
            if state_content
                write_file(@state_path, state_content)
                restored << "state"
            else
                $stderr.puts "Backup: gist does not contain #{STATE_GIST_FILENAME}"
            end

            queue_content = data.dig("files", QUEUE_GIST_FILENAME, "content")
            if queue_content
                write_file(@queue_path, queue_content)
                restored << "queue"
            end

            if restored.any?
                $stderr.puts "Backup: restored #{restored.join(", ")} from gist"
                true
            else
                $stderr.puts "Backup: gist contained no known files"
                false
            end
        rescue => e
            $stderr.puts "Backup: error restoring: #{e.message}"
            false
        end

        private

        def write_file(path, content)
            FileUtils.mkdir_p(File.dirname(path))
            tmp = "#{path}.tmp"
            File.write(tmp, content)
            File.rename(tmp, path)
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
            when 204
                true
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

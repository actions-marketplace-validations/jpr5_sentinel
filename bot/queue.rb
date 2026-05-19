require "json"
require "securerandom"
require "time"

module Bot
    class Queue
        def initialize(path = nil)
            @path = path || ENV["SENTINEL_QUEUE_PATH"] || "bot/queue.json"
            @data = File.exist?(@path) ? JSON.parse(File.read(@path)) : { "pending" => [], "approved" => [], "rejected" => [] }

            # Auto-restore from gist backup if queue is empty and backup is configured
            if @data["pending"].empty? && @data["approved"].empty? && @data["rejected"].empty? &&
               ENV["SENTINEL_BACKUP_GIST_ID"] && ENV["GITHUB_TOKEN"]
                auto_restore_from_backup
            end
        end

        def save
            tmp = "#{@path}.tmp"
            File.write(tmp, JSON.pretty_generate(@data))
            File.rename(tmp, @path)
        end

        def add(repo:, title:, body:, files:, findings:, signoff: nil, type: "pr")
            @data["pending"] << {
                "id" => SecureRandom.uuid,
                "repo" => repo,
                "title" => title,
                "body" => body,
                "files" => files,
                "findings" => findings.map { |f|
                    if f.is_a?(Hash)
                        f.transform_keys(&:to_s)
                    else
                        { "rule" => f.rule, "file" => f.file, "line" => f.line, "message" => f.message }
                    end
                },
                "signoff" => signoff,
                "type" => type,
                "queued_at" => Time.now.utc.iso8601,
            }
        end

        def pending = @data["pending"]
        def approved = @data["approved"]
        def rejected = @data["rejected"]

        def find(id)
            @data["pending"].find { |i| i["id"] == id }
        end

        def approve(id)
            item = @data["pending"].find { |i| i["id"] == id }
            return nil unless item
            @data["pending"].delete(item)
            @data["approved"] << item.merge("approved_at" => Time.now.utc.iso8601)
            item
        end

        def reject(id, reason: nil)
            item = @data["pending"].find { |i| i["id"] == id }
            return nil unless item
            @data["pending"].delete(item)
            @data["rejected"] << item.merge("rejected_at" => Time.now.utc.iso8601, "reason" => reason)
            item
        end

        def size
            @data["pending"].length
        end

        private

        def auto_restore_from_backup
            require_relative "backup"
            $stderr.puts "Queue is empty — restoring from gist backup..."
            backup = Backup.new(token: ENV["GITHUB_TOKEN"], queue_path: @path)
            backup.restore
            # Re-read the restored file
            if File.exist?(@path)
                restored = JSON.parse(File.read(@path))
                total = (restored["pending"]&.length || 0) +
                        (restored["approved"]&.length || 0) +
                        (restored["rejected"]&.length || 0)
                if total > 0
                    @data = restored
                    $stderr.puts "Restored #{total} queue items from backup"
                end
            end
        rescue => e
            $stderr.puts "Queue auto-restore failed (non-fatal): #{e.message}"
        end
    end
end

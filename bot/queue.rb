require "json"
require "securerandom"
require "time"

module Bot
    class Queue
        def initialize(path = nil)
            @path = path || ENV["SENTINEL_QUEUE_PATH"] || "bot/queue.json"
            @data = File.exist?(@path) ? JSON.parse(File.read(@path)) : { "pending" => [], "approved" => [], "rejected" => [] }
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
    end
end

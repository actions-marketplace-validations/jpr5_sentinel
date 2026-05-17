require "openssl"
require "json"
require "net/http"
require "uri"
require "base64"

module Bot
    class GitHubAppAuth
        API_BASE = "https://api.github.com"

        def initialize(app_id: nil, private_key_pem: nil)
            @app_id = app_id || ENV["GITHUB_APP_ID"]
            @private_key = OpenSSL::PKey::RSA.new(private_key_pem || ENV["GITHUB_APP_PRIVATE_KEY"])
            @installation_tokens = {}
        end

        def token_for(repo)
            # Check cache (tokens last 1 hour, refresh at 50 min)
            cached = @installation_tokens[repo]
            if cached && (Time.now.utc - cached[:created_at]) < 3000
                return cached[:token]
            end

            installation_id = get_installation_id(repo)
            return nil unless installation_id

            token = create_installation_token(installation_id)
            return nil unless token

            @installation_tokens[repo] = { token: token, created_at: Time.now.utc }
            token
        end

        private

        def generate_jwt
            now = Time.now.to_i
            payload = {
                iat: now - 60,        # issued at (60s in the past for clock drift)
                exp: now + (10 * 60), # expires in 10 minutes
                iss: @app_id.to_s
            }

            # RS256 signing
            header = Base64.urlsafe_encode64(JSON.generate({ alg: "RS256", typ: "JWT" }), padding: false)
            claims = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
            signature = Base64.urlsafe_encode64(
                @private_key.sign(OpenSSL::Digest::SHA256.new, "#{header}.#{claims}"),
                padding: false
            )

            "#{header}.#{claims}.#{signature}"
        end

        def get_installation_id(repo)
            jwt = generate_jwt
            uri = URI("#{API_BASE}/repos/#{repo}/installation")
            req = Net::HTTP::Get.new(uri)
            req["Authorization"] = "Bearer #{jwt}"
            req["Accept"] = "application/vnd.github+json"

            resp = execute(uri, req)
            resp&.dig("id")
        end

        def create_installation_token(installation_id)
            jwt = generate_jwt
            uri = URI("#{API_BASE}/app/installations/#{installation_id}/access_tokens")
            req = Net::HTTP::Post.new(uri)
            req["Authorization"] = "Bearer #{jwt}"
            req["Accept"] = "application/vnd.github+json"

            resp = execute(uri, req)
            resp&.dig("token")
        end

        def execute(uri, req)
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.open_timeout = 10
            http.read_timeout = 30

            resp = http.request(req)
            case resp.code.to_i
            when 200, 201
                JSON.parse(resp.body)
            else
                $stderr.puts "GitHub App auth error #{resp.code}: #{resp.body[0..200]}"
                nil
            end
        rescue StandardError => e
            $stderr.puts "GitHub App auth failed: #{e.message}"
            nil
        end
    end
end

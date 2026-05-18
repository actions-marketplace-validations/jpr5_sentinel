require "tmpdir"
require "fileutils"
require_relative "local_client"

class CloneClient
    REPO_FORMAT = %r{\A[A-Za-z0-9\-_.]+/[A-Za-z0-9\-_.]+\z}

    attr_reader :tmpdir

    def initialize
        @tmpdir = nil
    end

    def fetch_workflows(repo)
        unless repo.match?(REPO_FORMAT)
            $stderr.puts "Invalid repo format: #{repo} (expected owner/repo)"
            return []
        end

        @tmpdir = Dir.mktmpdir("sentinel-")

        success = try_clone(repo)

        unless success
            $stderr.puts ""
            $stderr.puts "ERROR: Could not access #{repo}"
            $stderr.puts ""
            $stderr.puts "If this is a private repo, make sure git can authenticate:"
            $stderr.puts "  - SSH key configured (git clone git@github.com:#{repo})"
            $stderr.puts "  - Or: gh auth login"
            $stderr.puts "  - Or: export GITHUB_TOKEN=$(gh auth token)"
            $stderr.puts ""
            exit 2
        end

        system(
            "git", "-C", @tmpdir, "sparse-checkout", "set", ".github",
            [:out, :err] => File::NULL
        )

        LocalClient.new(@tmpdir).fetch_workflows(repo)
    end

    def fetch_dependabot_config(repo)
        return nil unless @tmpdir
        LocalClient.new(@tmpdir).fetch_dependabot_config(repo)
    end

    def file_exists?(repo, path)
        return false unless @tmpdir
        File.exist?(File.join(@tmpdir, path))
    end

    def cleanup
        FileUtils.rm_rf(@tmpdir) if @tmpdir
    end

    private

    CLONE_ARGS = %w[--depth 1 --filter=blob:none --sparse].freeze

    def try_clone(repo)
        # 1. HTTPS — works for public repos and if credential helper is configured
        return true if try_url("https://github.com/#{repo}.git")

        # 2. SSH — works if SSH key is configured
        return true if try_url("git@github.com:#{repo}.git")

        # 3. HTTPS with gh auth token via credential helper (token never in URL or argv)
        token = detect_gh_token
        if token
            return true if try_url_with_token(repo, token)
        end

        false
    end

    def try_url(url)
        FileUtils.rm_rf(Dir.children(@tmpdir)) if @tmpdir && File.directory?(@tmpdir)
        system("git", "clone", *CLONE_ARGS, url, @tmpdir, [:out, :err] => File::NULL)
    end

    def try_url_with_token(repo, token)
        require "tempfile"
        FileUtils.rm_rf(Dir.children(@tmpdir)) if @tmpdir && File.directory?(@tmpdir)

        # Write a temporary credential file so the token never appears in argv or /proc
        cred_file = Tempfile.new("git-cred-", @tmpdir)
        begin
            cred_file.write("https://x-access-token:#{token}@github.com\n")
            cred_file.flush
            cred_file.close

            env = { "GIT_TERMINAL_PROMPT" => "0" }
            system(
                env,
                "git",
                "-c", "credential.helper=store --file=#{cred_file.path}",
                "clone", *CLONE_ARGS,
                "https://github.com/#{repo}.git", @tmpdir,
                [:out, :err] => File::NULL
            )
        ensure
            cred_file.close! rescue nil
        end
    end

    def detect_gh_token
        return ENV["GITHUB_TOKEN"] if ENV["GITHUB_TOKEN"]

        gh_path = `which gh 2>/dev/null`.strip
        return nil if gh_path.empty?
        return nil unless system("gh", "auth", "status", [:out, :err] => File::NULL)

        token = `gh auth token 2>/dev/null`.strip
        token.empty? ? nil : token
    end
end

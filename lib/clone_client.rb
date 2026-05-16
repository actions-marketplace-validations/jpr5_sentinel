require "tmpdir"
require "fileutils"
require_relative "local_client"

class CloneClient
    REPO_FORMAT = %r{\A[A-Za-z0-9\-_.]+/[A-Za-z0-9\-_.]+\z}

    def initialize
        @tmpdir = nil
    end

    def fetch_workflows(repo)
        unless repo.match?(REPO_FORMAT)
            $stderr.puts "Invalid repo format: #{repo} (expected owner/repo)"
            return []
        end

        @tmpdir = Dir.mktmpdir("sentinel-")

        # Shallow sparse clone — only .github/ directory
        success = system(
            "git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
            "https://github.com/#{repo}.git", @tmpdir,
            [:out, :err] => File::NULL
        )

        unless success
            $stderr.puts ""
            $stderr.puts "ERROR: Could not access #{repo}"
            $stderr.puts ""
            $stderr.puts "This repo may be private. To scan private repos:"
            $stderr.puts ""
            $stderr.puts "  export GITHUB_TOKEN=$(gh auth token)"
            $stderr.puts "  sentinel scan #{repo}"
            $stderr.puts ""
            $stderr.puts "Or pass a token directly:"
            $stderr.puts ""
            $stderr.puts "  sentinel scan --token ghp_xxx #{repo}"
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
end

module Bot
    class RepoConventions
        def initialize(token:)
            @client = GitHubClient.new(token: token)
        end

        def detect(repo_name)
            {
                dco: requires_dco?(repo_name),
                cla: detect_cla(repo_name),
                conventional_commits: requires_conventional_commits?(repo_name),
                pr_template: has_pr_template?(repo_name),
            }
        end

        def requires_dco?(repo_name)
            @client.file_exists?(repo_name, ".github/dco.yml") ||
                contributing_mentions?(repo_name, /DCO|sign.off|Signed-off-by/i)
        end

        def detect_cla(repo_name)
            # Google CLA
            return :google if contributing_mentions?(repo_name, /Google.*CLA|cla\/google/i)
            # Apache CLA
            return :apache if contributing_mentions?(repo_name, /Apache.*CLA|ICLA/i)
            # Generic CLA
            return :generic if contributing_mentions?(repo_name, /\bCLA\b.*sign|Contributor License Agreement/i)
            nil
        end

        def requires_conventional_commits?(repo_name)
            @client.file_exists?(repo_name, ".commitlintrc") ||
                @client.file_exists?(repo_name, ".commitlintrc.js") ||
                @client.file_exists?(repo_name, ".commitlintrc.json") ||
                @client.file_exists?(repo_name, ".commitlintrc.yml") ||
                @client.file_exists?(repo_name, "commitlint.config.js") ||
                @client.file_exists?(repo_name, "commitlint.config.ts") ||
                contributing_mentions?(repo_name, /conventional commit|commitlint/i)
        end

        def has_pr_template?(repo_name)
            @client.file_exists?(repo_name, ".github/PULL_REQUEST_TEMPLATE.md") ||
                @client.file_exists?(repo_name, ".github/pull_request_template.md") ||
                @client.file_exists?(repo_name, "PULL_REQUEST_TEMPLATE.md")
        end

        private

        def contributing_mentions?(repo_name, pattern)
            %w[CONTRIBUTING.md CONTRIBUTING contributing.md].each do |file|
                content = @client.fetch_file_content(repo_name, file)
                return true if content&.match?(pattern)
            end
            false
        end
    end
end

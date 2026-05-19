class LocalClient
    def initialize(path)
        @path = File.expand_path(path)
        @workflows_dir = File.join(@path, ".github", "workflows")
    end

    def fetch_workflows(_repo = nil)
        workflows = []
        return workflows unless File.directory?(@workflows_dir)

        Dir[File.join(@workflows_dir, "*.{yml,yaml}")].sort.each do |f|
            content = File.read(f)
            workflows << { filename: File.basename(f), content: content }
        end

        workflows
    end

    def file_exists?(_repo, path)
        File.exist?(File.join(@path, path))
    end

    def fetch_dependabot_config(_repo)
        path = File.join(@path, ".github", "dependabot.yml")
        path = File.join(@path, ".github", "dependabot.yaml") unless File.exist?(path)
        return nil unless File.exist?(path)
        begin
            YAML.safe_load(File.read(path), aliases: true)
        rescue StandardError => e
            nil
        end
    end

    def fetch_platform_configs
        configs = []

        # GitLab CI
        %w[.gitlab-ci.yml .gitlab-ci.yaml].each do |name|
            path = File.join(@path, name)
            if File.exist?(path)
                configs << { platform: :gitlab, filename: name, content: File.read(path) }
                break
            end
        end

        # Bitbucket Pipelines
        %w[bitbucket-pipelines.yml bitbucket-pipelines.yaml].each do |name|
            path = File.join(@path, name)
            if File.exist?(path)
                configs << { platform: :bitbucket, filename: name, content: File.read(path) }
                break
            end
        end

        configs
    end
end

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
            YAML.safe_load(File.read(path))
        rescue StandardError => e
            nil
        end
    end
end

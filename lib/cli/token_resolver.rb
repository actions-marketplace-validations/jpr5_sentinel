module TokenResolver
    def self.resolve(options)
        return options[:token] if options[:token]
        return ENV["GITHUB_TOKEN"] if ENV["GITHUB_TOKEN"]

        gh_path = `which gh 2>/dev/null`.strip
        if !gh_path.empty? && system("gh", "auth", "status", [:out, :err] => File::NULL)
            token = `gh auth token 2>/dev/null`.strip
            return token unless token.empty?
        end

        nil
    end
end

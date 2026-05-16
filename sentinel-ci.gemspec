Gem::Specification.new do |s|
    s.name        = "sentinel-ci"
    s.version     = File.read(File.join(__dir__, "lib", "version.rb"))[/VERSION\s*=\s*"([^"]+)"/, 1]
    s.summary     = "Deterministic security scanner for GitHub Actions workflows"
    s.description = "Scan GitHub Actions workflows for 28 security vulnerabilities. " \
                    "SHA pinning, shell injection, credential exposure, dangerous triggers. " \
                    "No AI, no dependencies — pure Ruby stdlib."
    s.authors     = ["Jordan Ritter"]
    s.email       = "jpr5@darkridge.com"
    s.homepage    = "https://sentinel.copilotkit.dev"
    s.license     = "MIT"
    s.metadata    = {
        "source_code_uri" => "https://github.com/jpr5/sentinel",
        "bug_tracker_uri" => "https://github.com/jpr5/sentinel/issues",
        "homepage_uri"    => "https://sentinel.copilotkit.dev",
    }

    s.required_ruby_version = ">= 3.2"
    s.files       = Dir["lib/**/*.rb", "bin/*", "LICENSE", "README.md", "CHANGELOG.md"]
    s.executables = ["sentinel"]

    # Zero dependencies — pure stdlib
end

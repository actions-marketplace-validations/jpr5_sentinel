require_relative "test_helper"
require_relative "../lib/supply_chain"

class TestSupplyChain < Minitest::Test
    def setup
        @chain = SupplyChain.new(token: nil)
    end

    # --- extract_actions ---

    def test_extract_finds_third_party_actions
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: softprops/action-gh-release@v1
        YAML

        results = @chain.analyze([wf])
        repos = results.map { |a| a[:repo] }
        assert_includes repos, "softprops/action-gh-release"
    end

    def test_skips_local_actions
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: ./local-action
                  - uses: softprops/action-gh-release@v1
        YAML

        results = @chain.analyze([wf])
        repos = results.map { |a| a[:repo] }
        refute repos.any? { |r| r.include?("local-action") }
        assert_includes repos, "softprops/action-gh-release"
    end

    def test_skips_docker_actions
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: docker://alpine:3.18
                  - uses: pnpm/action-setup@v2
        YAML

        results = @chain.analyze([wf])
        repos = results.map { |a| a[:repo] }
        refute repos.any? { |r| r.include?("docker") || r.include?("alpine") }
        assert_includes repos, "pnpm/action-setup"
    end

    def test_marks_first_party_actions
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: github/codeql-action/init@v2
                  - uses: softprops/action-gh-release@v1
        YAML

        results = @chain.analyze([wf])
        checkout = results.find { |a| a[:repo] == "actions/checkout" }
        codeql = results.find { |a| a[:repo] == "github/codeql-action" }
        softprops = results.find { |a| a[:repo] == "softprops/action-gh-release" }

        assert checkout[:first_party], "actions/* should be first-party"
        assert codeql[:first_party], "github/* should be first-party"
        refute softprops[:first_party], "softprops/* should NOT be first-party"
    end

    def test_groups_by_repo_across_files
        wf1 = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: pnpm/action-setup@v2
        YAML

        wf2 = Workflow.new(filename: "release.yml", content: <<~YAML)
            on: push
            jobs:
              release:
                runs-on: ubuntu-latest
                steps:
                  - uses: pnpm/action-setup@v2
        YAML

        results = @chain.analyze([wf1, wf2])
        pnpm = results.find { |a| a[:repo] == "pnpm/action-setup" }

        assert pnpm, "pnpm/action-setup should be found"
        assert_equal 2, pnpm[:used_in].length, "Should be referenced in both files"
        files = pnpm[:used_in].map { |u| u[:file] }
        assert_includes files, "ci.yml"
        assert_includes files, "release.yml"
    end

    def test_groups_multiple_refs_for_same_repo
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: pnpm/action-setup@v2
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: pnpm/action-setup@v3
        YAML

        results = @chain.analyze([wf])
        pnpm = results.find { |a| a[:repo] == "pnpm/action-setup" }

        assert_includes pnpm[:refs], "v2"
        assert_includes pnpm[:refs], "v3"
    end

    # --- Risk scoring (unit-level via send) ---

    def test_risk_low_stars_higher_score
        action_low = { stars: 50, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        action_high = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }

        score_low = @chain.send(:calculate_risk, action_low)
        score_high = @chain.send(:calculate_risk, action_high)

        assert score_low > score_high, "Low stars (#{score_low}) should score higher risk than high stars (#{score_high})"
    end

    def test_risk_archived_higher_score
        action_active = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        action_archived = { stars: 5000, archived: true, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }

        score_active = @chain.send(:calculate_risk, action_active)
        score_archived = @chain.send(:calculate_risk, action_archived)

        assert score_archived > score_active, "Archived (#{score_archived}) should score higher risk than active (#{score_active})"
    end

    def test_risk_personal_account_higher_score
        action_org = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        action_user = { stars: 5000, archived: false, owner_type: "User", refs: ["abc123def456abc123def456abc123def456abcd"] }

        score_org = @chain.send(:calculate_risk, action_org)
        score_user = @chain.send(:calculate_risk, action_user)

        assert score_user > score_org, "Personal account (#{score_user}) should score higher risk than org (#{score_org})"
    end

    def test_risk_not_sha_pinned_higher_score
        action_pinned = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        action_unpinned = { stars: 5000, archived: false, owner_type: "Organization", refs: ["v2"] }

        score_pinned = @chain.send(:calculate_risk, action_pinned)
        score_unpinned = @chain.send(:calculate_risk, action_unpinned)

        assert score_unpinned > score_pinned, "Unpinned (#{score_unpinned}) should score higher risk than SHA-pinned (#{score_pinned})"
    end

    def test_risk_stale_repo_higher_score
        action_fresh = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"], last_push: Time.now.strftime("%Y-%m-%dT%H:%M:%SZ") }
        action_stale = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"], last_push: "2020-01-01T00:00:00Z" }

        score_fresh = @chain.send(:calculate_risk, action_fresh)
        score_stale = @chain.send(:calculate_risk, action_stale)

        assert score_stale > score_fresh, "Stale repo (#{score_stale}) should score higher risk than fresh (#{score_fresh})"
    end

    # --- identify_risks ---

    def test_identify_risks_low_stars
        action = { stars: 50, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        risks = @chain.send(:identify_risks, action)
        assert risks.any? { |r| r.include?("Low stars") }
    end

    def test_identify_risks_archived
        action = { stars: 5000, archived: true, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"] }
        risks = @chain.send(:identify_risks, action)
        assert risks.any? { |r| r.include?("Archived") }
    end

    def test_identify_risks_personal_account
        action = { stars: 5000, archived: false, owner_type: "User", refs: ["abc123def456abc123def456abc123def456abcd"] }
        risks = @chain.send(:identify_risks, action)
        assert risks.any? { |r| r.include?("Personal account") }
    end

    def test_identify_risks_not_sha_pinned
        action = { stars: 5000, archived: false, owner_type: "Organization", refs: ["v2"] }
        risks = @chain.send(:identify_risks, action)
        assert risks.any? { |r| r.include?("SHA-pinned") }
    end

    def test_identify_risks_stale
        action = { stars: 5000, archived: false, owner_type: "Organization", refs: ["abc123def456abc123def456abc123def456abcd"], last_push: "2020-01-01T00:00:00Z" }
        risks = @chain.send(:identify_risks, action)
        assert risks.any? { |r| r.include?("Stale") }
    end

    def test_no_enrichment_without_token
        wf = Workflow.new(filename: "ci.yml", content: <<~YAML)
            on: push
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: softprops/action-gh-release@v1
        YAML

        # Without a token, enrich should not add stars/risk data
        results = @chain.analyze([wf])
        softprops = results.find { |a| a[:repo] == "softprops/action-gh-release" }
        assert_nil softprops[:stars], "Without token, stars should not be populated"
        assert_nil softprops[:risk_score], "Without token, risk_score should not be populated"
    end
end

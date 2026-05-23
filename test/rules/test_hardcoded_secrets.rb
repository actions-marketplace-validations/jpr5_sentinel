require_relative "../test_helper"

class TestHardcodedSecrets < Minitest::Test
    def setup
        @rule = Rules::HardcodedSecrets.new
    end

    def test_flags_aws_access_key
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  run: |
                    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_equal :critical, findings.first.severity
        assert_match(/AWS access key/, findings.first.message)
    end

    def test_flags_github_pat
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Clone
                  run: |
                    git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij@github.com/org/repo
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_equal 1, findings.length
        assert_match(/GitHub personal access token/, findings.first.message)
    end

    def test_safe_when_using_secrets_expression
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Deploy
                  env:
                    API_KEY: ${{ secrets.API_KEY }}
                  run: echo "deploying"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_safe_when_line_is_comment
        yaml = <<~YAML
          on: push
          # AKIAIOSFODNN7EXAMPLE is an example key
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "hello"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_empty findings
    end

    def test_flags_hardcoded_password
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: |
                    password: mysecretpassword123
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        assert_operator findings.length, :>=, 1
        has_password_finding = findings.any? { |f| f.message.match?(/password/i) }
        assert has_password_finding, "Expected a password-related finding"
    end

    def test_safe_password_with_secrets_ref
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: |
                    password: ${{ secrets.DB_PASSWORD }}
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end

    def test_safe_password_true
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              services:
                mariadb:
                  image: mariadb:latest
                  env:
                    MARIADB_ALLOW_EMPTY_ROOT_PASSWORD: true
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end

    def test_safe_password_false
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              services:
                db:
                  image: postgres:latest
                  env:
                    SOME_PASSWORD: false
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end

    def test_bare_uppercase_env_var_name_is_safe
        # actions/setup-java uses bare env-var-name references for server-password:
        # e.g. `server-password: MAVEN_PASSWORD` means "read the MAVEN_PASSWORD env var",
        # not a literal password value. Same convention for GITHUB_TOKEN, MY_SECRET_KEY, etc.
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/setup-java@v4
                  with:
                    server-password: MAVEN_PASSWORD
                - name: Step 2
                  with:
                    password: GITHUB_TOKEN
                - name: Step 3
                  with:
                    password: MY_SECRET_KEY
                - name: Step 4
                  with:
                    password: A_B_C_123
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings, "Bare uppercase env-var-name references should not trigger"
    end

    def test_literal_uppercase_password_with_special_chars_still_fires
        # Mixed case + special characters means it's an actual password literal,
        # not an env-var reference. Must still flag.
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: |
                    password: MyPass!123
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        refute_empty password_findings, "Literal mixed-case password with special chars should still be flagged"
    end

    def test_existing_safe_patterns_still_safe
        # Regression: ${{ secrets.X }} and $VAR references must remain safe.
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Step 1
                  with:
                    password: ${{ secrets.DB_PASSWORD }}
                - name: Step 2
                  run: |
                    password: $MY_VAR
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end

    def test_existing_safe_passwords_still_safe
        # Regression: common test placeholder passwords must remain safe.
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              services:
                db:
                  image: postgres:latest
                  env:
                    POSTGRES_PASSWORD: postgres
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings
    end

    # --- setup-java env-var-name slot tests ---

    def test_safe_setup_java_server_password_env_var_name
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/setup-java@v4
                  with:
                    distribution: temurin
                    java-version: 11
                    server-id: ossrh
                    server-password: MAVEN_PASSWORD
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings, "server-password with UPPER_SNAKE env var name should not fire"
    end

    def test_safe_setup_java_server_username_env_var_name
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/setup-java@v4
                  with:
                    distribution: temurin
                    java-version: 11
                    server-id: ossrh
                    server-username: MAVEN_USERNAME
                    server-password: MAVEN_PASSWORD
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        # server-username doesn't match PASSWORD_PATTERN, but verify no false positives overall
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings, "setup-java env var name slots should not fire"
    end

    def test_safe_setup_java_gpg_passphrase_env_var_name
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/setup-java@v4
                  with:
                    distribution: temurin
                    java-version: 11
                    gpg-passphrase: MAVEN_GPG_PASSPHRASE
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_empty password_findings, "gpg-passphrase with UPPER_SNAKE env var name should not fire"
    end

    def test_flags_setup_java_literal_password_in_env_slot
        yaml = <<~YAML
          on: push
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/setup-java@v4
                  with:
                    distribution: temurin
                    java-version: 11
                    server-id: ossrh
                    server-password: my-actual-secret-value
        YAML
        wf = Workflow.new(filename: "publish.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_operator password_findings.length, :>=, 1,
            "Literal password value in setup-java slot should still fire"
    end

    def test_flags_password_in_generic_step
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: echo "password: secret123"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        password_findings = findings.select { |f| f.message.match?(/password/i) }
        assert_operator password_findings.length, :>=, 1,
            "Hardcoded password in generic step should still fire"
    end

    def test_flags_password_akia_in_generic_step
        yaml = <<~YAML
          on: push
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - name: Login
                  run: echo "password: AKIAIOSFODNN7EXAMPLE"
        YAML
        wf = Workflow.new(filename: "ci.yml", content: yaml)
        findings = @rule.check(wf)
        # Should fire for AWS key AND/OR password
        assert_operator findings.length, :>=, 1,
            "AKIA key as password value should fire"
    end
end

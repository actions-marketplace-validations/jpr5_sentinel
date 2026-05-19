require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "json"

require_relative "../../bot/config"
require_relative "../../bot/backup"

class TestBotBackup < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-backup-test")
        @state_file = File.join(@tmpdir, "state.json")
        @queue_file = File.join(@tmpdir, "queue.json")
        @token = "test-token"
        @sample_state = {"repos" => {"owner/repo" => {"scans" => [], "prs" => []}}, "opt_outs" => []}
        @sample_queue = {"pending" => [{"id" => "abc-123", "repo" => "owner/repo"}], "approved" => [], "rejected" => []}
        File.write(@state_file, JSON.pretty_generate(@sample_state))
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def stub_api(backup, responses = {})
        backup.define_singleton_method(:api_get) { |path| responses[path] }
        backup.define_singleton_method(:api_post) { |path, body|
            responses["POST:#{path}"] || responses[:post]
        }
        backup.define_singleton_method(:api_patch) { |path, body|
            responses["PATCH:#{path}"] || responses[:patch]
        }
    end

    # --- State-only save/restore (backward compat) ---

    def test_save_creates_gist_when_no_gist_id
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        created_gist = {"id" => "abc123", "files" => {}}
        stub_api(backup, { post: created_gist })

        assert backup.save
    end

    def test_save_updates_existing_gist_when_gist_id_set
        ENV["SENTINEL_BACKUP_GIST_ID"] = "existing-gist-id"
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        updated_gist = {"id" => "existing-gist-id", "files" => {}}
        stub_api(backup, { "PATCH:/gists/existing-gist-id" => updated_gist })

        assert backup.save
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_fetches_and_writes_state
        ENV["SENTINEL_BACKUP_GIST_ID"] = "restore-gist-id"
        restore_path = File.join(@tmpdir, "restored-state.json")
        backup = Bot::Backup.new(token: @token, state_path: restore_path)

        gist_content = JSON.pretty_generate(@sample_state)
        gist_response = {
            "id" => "restore-gist-id",
            "files" => {
                "sentinel-state-backup.json" => { "content" => gist_content },
            },
        }
        stub_api(backup, { "/gists/restore-gist-id" => gist_response })

        assert backup.restore
        assert File.exist?(restore_path)
        assert_equal @sample_state, JSON.parse(File.read(restore_path))
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_save_handles_network_errors_gracefully
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        stub_api(backup, { post: nil })

        refute backup.save
    end

    def test_restore_handles_network_errors_gracefully
        ENV["SENTINEL_BACKUP_GIST_ID"] = "error-gist-id"
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        stub_api(backup, { "/gists/error-gist-id" => nil })

        refute backup.restore
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_fails_gracefully_when_no_gist_id
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        backup = Bot::Backup.new(token: @token, state_path: @state_file)

        refute backup.restore
    end

    def test_save_with_missing_state_file
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        missing_path = File.join(@tmpdir, "nonexistent.json")
        backup = Bot::Backup.new(token: @token, state_path: missing_path)

        refute backup.save
    end

    # --- Multi-file (state + queue) save/restore ---

    def test_save_includes_queue_when_present
        File.write(@queue_file, JSON.pretty_generate(@sample_queue))
        ENV["SENTINEL_BACKUP_GIST_ID"] = "multi-gist-id"

        backup = Bot::Backup.new(token: @token, state_path: @state_file, queue_path: @queue_file)

        captured_files = nil
        backup.define_singleton_method(:api_patch) { |path, body|
            captured_files = body[:files]
            {"id" => "multi-gist-id", "files" => {}}
        }
        backup.define_singleton_method(:api_get) { |path| nil }
        backup.define_singleton_method(:api_post) { |path, body| nil }

        assert backup.save
        assert captured_files.key?("sentinel-state-backup.json"), "Should include state file"
        assert captured_files.key?("sentinel-queue-backup.json"), "Should include queue file"
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_save_omits_queue_when_missing
        ENV["SENTINEL_BACKUP_GIST_ID"] = "state-only-gist"
        # queue_file does not exist

        backup = Bot::Backup.new(token: @token, state_path: @state_file, queue_path: @queue_file)

        captured_files = nil
        backup.define_singleton_method(:api_patch) { |path, body|
            captured_files = body[:files]
            {"id" => "state-only-gist", "files" => {}}
        }
        backup.define_singleton_method(:api_get) { |path| nil }
        backup.define_singleton_method(:api_post) { |path, body| nil }

        assert backup.save
        assert captured_files.key?("sentinel-state-backup.json"), "Should include state file"
        refute captured_files.key?("sentinel-queue-backup.json"), "Should not include missing queue file"
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_writes_both_state_and_queue
        ENV["SENTINEL_BACKUP_GIST_ID"] = "both-gist-id"
        restore_state = File.join(@tmpdir, "restore-state.json")
        restore_queue = File.join(@tmpdir, "restore-queue.json")

        backup = Bot::Backup.new(token: @token, state_path: restore_state, queue_path: restore_queue)

        gist_response = {
            "id" => "both-gist-id",
            "files" => {
                "sentinel-state-backup.json" => { "content" => JSON.pretty_generate(@sample_state) },
                "sentinel-queue-backup.json" => { "content" => JSON.pretty_generate(@sample_queue) },
            },
        }
        stub_api(backup, { "/gists/both-gist-id" => gist_response })

        assert backup.restore
        assert File.exist?(restore_state), "State file should be restored"
        assert File.exist?(restore_queue), "Queue file should be restored"
        assert_equal @sample_state, JSON.parse(File.read(restore_state))
        assert_equal @sample_queue, JSON.parse(File.read(restore_queue))
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_restore_succeeds_with_state_only_in_gist
        ENV["SENTINEL_BACKUP_GIST_ID"] = "state-only-restore"
        restore_state = File.join(@tmpdir, "restore-state2.json")
        restore_queue = File.join(@tmpdir, "restore-queue2.json")

        backup = Bot::Backup.new(token: @token, state_path: restore_state, queue_path: restore_queue)

        gist_response = {
            "id" => "state-only-restore",
            "files" => {
                "sentinel-state-backup.json" => { "content" => JSON.pretty_generate(@sample_state) },
            },
        }
        stub_api(backup, { "/gists/state-only-restore" => gist_response })

        assert backup.restore
        assert File.exist?(restore_state), "State file should be restored"
        refute File.exist?(restore_queue), "Queue file should not exist when not in gist"
    ensure
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
    end

    def test_default_queue_path_derives_from_state_path
        backup = Bot::Backup.new(token: @token, state_path: "/some/dir/state.json")
        assert_equal "/some/dir/queue.json", backup.instance_variable_get(:@queue_path)
    end

    def test_explicit_queue_path_overrides_default
        backup = Bot::Backup.new(token: @token, state_path: "/some/dir/state.json", queue_path: "/other/queue.json")
        assert_equal "/other/queue.json", backup.instance_variable_get(:@queue_path)
    end

    def test_save_fails_when_no_files_exist
        ENV.delete("SENTINEL_BACKUP_GIST_ID")
        missing_state = File.join(@tmpdir, "nope-state.json")
        missing_queue = File.join(@tmpdir, "nope-queue.json")
        backup = Bot::Backup.new(token: @token, state_path: missing_state, queue_path: missing_queue)

        refute backup.save
    end
end

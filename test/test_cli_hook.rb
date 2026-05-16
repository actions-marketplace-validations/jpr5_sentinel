require_relative "test_helper"
require "tmpdir"
require "fileutils"

class TestCliHook < Minitest::Test
    def setup
        @tmpdir = Dir.mktmpdir("sentinel-hook-test")
        # Initialize a git repo in the temp dir
        system("git", "init", @tmpdir, [:out, :err] => File::NULL)
    end

    def teardown
        FileUtils.rm_rf(@tmpdir)
    end

    def test_hook_script_contains_sentinel
        hook_content = hook_script_content
        assert_includes hook_content, "sentinel"
        assert_includes hook_content, "git diff --cached"
        assert_includes hook_content, ".github/workflows"
    end

    def test_install_creates_hook_file
        hook_path = File.join(@tmpdir, ".git", "hooks", "pre-commit")
        refute File.exist?(hook_path), "hook should not exist before install"

        install_hook

        assert File.exist?(hook_path), "hook should exist after install"
        assert File.executable?(hook_path), "hook should be executable"

        content = File.read(hook_path)
        assert_includes content, "sentinel"
        assert_includes content, "#!/usr/bin/env bash"
    end

    def test_install_appends_to_existing_hook
        hook_dir = File.join(@tmpdir, ".git", "hooks")
        FileUtils.mkdir_p(hook_dir)
        hook_path = File.join(hook_dir, "pre-commit")
        File.write(hook_path, "#!/usr/bin/env bash\necho 'existing hook'\n")
        File.chmod(0o755, hook_path)

        install_hook

        content = File.read(hook_path)
        assert_includes content, "existing hook"
        assert_includes content, "sentinel"
        # Should not have duplicate shebang
        assert_equal 1, content.scan("#!/usr/bin/env bash").length
    end

    def test_install_idempotent
        install_hook
        install_hook  # second install should not duplicate

        hook_path = File.join(@tmpdir, ".git", "hooks", "pre-commit")
        content = File.read(hook_path)
        assert_equal 1, content.scan("sentinel pre-commit hook begin").length
    end

    def test_uninstall_removes_hook
        install_hook

        hook_path = File.join(@tmpdir, ".git", "hooks", "pre-commit")
        assert File.exist?(hook_path)

        uninstall_hook

        refute File.exist?(hook_path), "hook file should be removed after uninstall"
    end

    def test_uninstall_preserves_other_hooks
        hook_dir = File.join(@tmpdir, ".git", "hooks")
        FileUtils.mkdir_p(hook_dir)
        hook_path = File.join(hook_dir, "pre-commit")
        File.write(hook_path, "#!/usr/bin/env bash\necho 'existing hook'\n")
        File.chmod(0o755, hook_path)

        install_hook
        uninstall_hook

        assert File.exist?(hook_path), "hook file should remain when other content exists"
        content = File.read(hook_path)
        assert_includes content, "existing hook"
        refute_includes content, "sentinel pre-commit hook begin"
    end

    def test_uninstall_no_hook_exits_cleanly
        # No hook file at all — should not error
        pid = spawn("ruby", hook_rb_path, "uninstall",
                    chdir: @tmpdir,
                    [:out, :err] => File::NULL)
        _, status = Process.wait2(pid)
        assert_equal 0, status.exitstatus, "uninstall with no hook should exit 0"
    end

    def test_hook_run_no_staged_files_exits_zero
        # In a git repo with no staged workflow files, hook run should exit 0
        File.write(File.join(@tmpdir, "readme.txt"), "hello")
        system("git", "-C", @tmpdir, "add", "readme.txt", [:out, :err] => File::NULL)

        pid = spawn("ruby", hook_rb_path, "run",
                    chdir: @tmpdir,
                    [:out, :err] => File::NULL)
        _, status = Process.wait2(pid)
        assert_equal 0, status.exitstatus, "hook run should exit 0 when no workflow files staged"
    end

    private

    def hook_rb_path
        File.expand_path("../lib/cli/hook.rb", __dir__)
    end

    def hook_script_content
        require hook_rb_path.sub(/\.rb$/, "")
        HOOK_SCRIPT
    rescue SystemExit
        HOOK_SCRIPT
    end

    def install_hook
        pid = spawn("ruby", hook_rb_path, "install",
                    chdir: @tmpdir,
                    [:out, :err] => File::NULL)
        _, status = Process.wait2(pid)
        assert_equal 0, status.exitstatus, "hook install should exit 0"
    end

    def uninstall_hook
        pid = spawn("ruby", hook_rb_path, "uninstall",
                    chdir: @tmpdir,
                    [:out, :err] => File::NULL)
        _, status = Process.wait2(pid)
        assert_equal 0, status.exitstatus, "hook uninstall should exit 0"
    end
end

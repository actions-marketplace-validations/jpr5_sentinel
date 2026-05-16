require_relative "sha_resolver"
require_relative "finding"

module AutoFix
    FIXABLE_RULES = %w[
        unpinned-actions
        shell-injection-expr
        missing-persist-credentials
    ].freeze

    # Context expression -> env var name mappings
    ENV_VAR_NAMES = {
        "github.event.pull_request.title"      => "PR_TITLE",
        "github.event.pull_request.body"       => "PR_BODY",
        "github.event.pull_request.head.ref"   => "PR_HEAD_REF",
        "github.event.pull_request.head.label" => "PR_HEAD_LABEL",
        "github.event.issue.title"             => "ISSUE_TITLE",
        "github.event.issue.body"              => "ISSUE_BODY",
        "github.event.comment.body"            => "COMMENT_BODY",
        "github.event.review.body"             => "REVIEW_BODY",
        "github.event.discussion.title"        => "DISCUSSION_TITLE",
        "github.event.discussion.body"         => "DISCUSSION_BODY",
        "github.event.workflow_run.head_branch" => "WORKFLOW_HEAD_BRANCH",
        "github.head_ref"                      => "HEAD_REF",
        "github.actor"                         => "GH_ACTOR",
        "github.triggering_actor"              => "TRIGGERING_ACTOR",
    }.freeze

    DANGEROUS_EXPR_PATTERN = /\$\{\{\s*(#{ENV_VAR_NAMES.keys.map { |k| Regexp.escape(k) }.join('|')})\s*\}\}/

    def self.can_fix?(finding)
        FIXABLE_RULES.include?(finding.rule)
    end

    def self.apply(finding, raw_content, sha_resolver: nil)
        lines = raw_content.gsub("\r\n", "\n").lines

        case finding.rule
        when "unpinned-actions"
            fix_unpinned_action(lines, finding, sha_resolver: sha_resolver)
        when "shell-injection-expr"
            fix_shell_injection(lines, finding)
        when "missing-persist-credentials"
            fix_persist_credentials(lines, finding)
        else
            raw_content
        end
    end

    # --- unpinned-actions ---

    def self.fix_unpinned_action(lines, finding, sha_resolver: nil)
        sha_resolver ||= ShaResolver.new

        # Extract the uses string from the finding code
        uses_string = extract_uses_string(finding.code)
        return lines.join unless uses_string
        return lines.join unless uses_string.include?("@")

        owner_action, tag = uses_string.split("@", 2)
        return lines.join if tag.nil? || tag.empty?

        # Strip any existing inline comment from the tag
        tag = tag.split("#").first.strip

        sha = sha_resolver.resolve(owner_action, tag)
        return lines.join unless sha

        target_idx = finding.line - 1
        return lines.join if target_idx < 0 || target_idx >= lines.length

        pinned = "#{owner_action}@#{sha} # #{tag}"
        lines[target_idx] = lines[target_idx].sub(uses_string) { pinned }

        lines.join
    end

    # --- shell-injection-expr ---

    def self.fix_shell_injection(lines, finding)
        target_idx = finding.line - 1
        return lines.join if target_idx < 0 || target_idx >= lines.length

        # Collect all dangerous expressions on this line
        line = lines[target_idx]
        expressions = line.scan(DANGEROUS_EXPR_PATTERN).flatten.uniq

        return lines.join if expressions.empty?

        # Find the step's run: line by walking backwards
        run_line_idx = find_run_line(lines, target_idx)
        return lines.join unless run_line_idx

        # Determine the step-level indentation (same as run:)
        run_indent = lines[run_line_idx][/^(\s*)/, 1]

        # Build env var mappings
        env_mappings = {}
        expressions.each do |expr|
            var_name = ENV_VAR_NAMES[expr]
            next unless var_name
            env_mappings[var_name] = "${{ #{expr} }}"
        end

        return lines.join if env_mappings.empty?

        # Check if there's already an env: block at the step level
        existing_env_idx = find_step_env_block(lines, run_line_idx, run_indent)

        if existing_env_idx
            # Insert new env vars into the existing env: block
            # Find the last entry in the env: block
            insert_idx = find_env_block_end(lines, existing_env_idx, run_indent)
            env_entry_indent = run_indent + "    "

            new_entries = env_mappings.map { |var, expr| "#{env_entry_indent}#{var}: #{expr}\n" }
            new_entries.reverse.each do |entry|
                lines.insert(insert_idx, entry)
            end
            # Adjust run_line_idx since entries were inserted before run:
            if insert_idx <= run_line_idx
                run_line_idx += new_entries.length
            end
        else
            # Insert env: block as individual lines before the run: line
            env_lines = ["#{run_indent}env:\n"]
            env_mappings.each do |var, expr|
                env_lines << "#{run_indent}    #{var}: #{expr}\n"
            end

            env_lines.reverse.each { |el| lines.insert(run_line_idx, el) }
            inserted_count = env_lines.length
            # Adjust run_line_idx to point to the actual run: line after insertion
            run_line_idx += inserted_count
        end

        # Replace ${{ context }} with $VAR in the run block lines
        run_block_range = find_run_block_range(lines, run_line_idx)

        run_block_range.each do |i|
            env_mappings.each do |var, _expr|
                context = ENV_VAR_NAMES.key(var)
                next unless context
                # Replace ${{ context }} with $VAR (for shell context)
                replacement = "$#{var}"
                lines[i] = lines[i].gsub(/\$\{\{\s*#{Regexp.escape(context)}\s*\}\}/) { replacement }
            end
        end

        lines.join
    end

    # --- missing-persist-credentials ---

    def self.fix_persist_credentials(lines, finding)
        target_idx = finding.line - 1
        return lines.join if target_idx < 0 || target_idx >= lines.length

        # Verify this is a checkout uses: line
        line = lines[target_idx]
        return lines.join unless line =~ /uses:\s*actions\/checkout/

        uses_indent = line[/^(\s*)/, 1]

        # Look for an existing with: block below the uses: line
        with_idx = nil
        search_end = [target_idx + 10, lines.length - 1].min

        (target_idx + 1..search_end).each do |i|
            current = lines[i]
            current_indent = current[/^(\s*)/, 1] || ""

            # If we hit a line at the same or lesser indentation as uses: that's
            # a new step key or a new step entirely, stop looking
            if current.strip.length > 0
                if current_indent.length <= uses_indent.length
                    break
                end

                if current =~ /^\s*with:\s*$/  || current =~ /^\s*with:\s+\S/
                    with_idx = i
                    break
                end

                # If we hit another step-level key (env:, name:, id:, if:, etc.)
                # that's at the same indent as uses:+2 spaces, stop
                if current =~ /^\s*(env|name|id|if|uses|with|continue-on-error|timeout-minutes|run|working-directory|shell):/
                    break
                end
            end
        end

        if with_idx
            # with: block exists, add persist-credentials: false to it
            with_indent = lines[with_idx][/^(\s*)/, 1]

            # Detect entry indent from first existing entry under with:
            entry_indent = nil
            (with_idx + 1..[with_idx + 10, lines.length - 1].min).each do |i|
                if lines[i].strip.length > 0
                    candidate_indent = lines[i][/^(\s*)/, 1] || ""
                    if candidate_indent.length > with_indent.length
                        entry_indent = candidate_indent
                    end
                    break
                end
            end
            entry_indent ||= with_indent + "  "

            # Check if persist-credentials is already there (shouldn't be since
            # the rule flagged it, but be safe)
            has_persist = false
            (with_idx + 1..search_end).each do |i|
                break if lines[i].strip.length > 0 && (lines[i][/^(\s*)/, 1] || "").length <= with_indent.length
                has_persist = true if lines[i] =~ /persist-credentials:/
            end

            unless has_persist
                # Find the right place to insert (right after with:)
                insert_at = with_idx + 1
                lines.insert(insert_at, "#{entry_indent}persist-credentials: false\n")
            end
        else
            # No with: block — add one at same indent as uses:, entry one level deeper
            entry_indent = uses_indent + "  "

            new_block = "#{uses_indent}with:\n#{entry_indent}persist-credentials: false\n"
            lines.insert(target_idx + 1, new_block)
        end

        lines.join
    end

    # --- Private helpers ---

    def self.extract_uses_string(code)
        return nil unless code
        match = code.match(/uses:\s*(.+)/)
        return nil unless match
        match[1].strip
    end

    def self.find_run_line(lines, from_idx)
        from_idx.downto([from_idx - 20, 0].max) do |i|
            return i if lines[i] =~ /^\s+run:\s*[\|>]?\s*$/ || lines[i] =~ /^\s+run:\s+\S/
        end
        nil
    end

    def self.find_step_env_block(lines, run_line_idx, run_indent)
        # Walk backwards from run: to find if there's an env: at the same indent
        # within this step (stop at step boundary: "- name:", "- uses:", etc.)
        (run_line_idx - 1).downto([run_line_idx - 15, 0].max) do |i|
            line = lines[i]
            line_indent = line[/^(\s*)/, 1] || ""

            # Step boundary
            return nil if line =~ /^\s*-\s+(name|uses|run|id|if):/
            return nil if line_indent.length < run_indent.length && line.strip.length > 0

            if line =~ /^#{Regexp.escape(run_indent)}env:\s*$/ || line =~ /^#{Regexp.escape(run_indent)}env:\s+\S/
                return i
            end
        end
        nil
    end

    def self.find_env_block_end(lines, env_idx, run_indent)
        # Find the line after the last entry in the env: block
        env_entry_indent = run_indent + "    "
        i = env_idx + 1
        while i < lines.length
            line = lines[i]
            line_indent = line[/^(\s*)/, 1] || ""
            break if line.strip.length > 0 && line_indent.length <= run_indent.length
            i += 1
        end
        i
    end

    def self.find_run_block_range(lines, run_line_idx)
        range = []
        run_indent = lines[run_line_idx][/^(\s*)/, 1]

        if lines[run_line_idx] =~ /^\s+run:\s*[|>]\s*$/
            # Multi-line run block — detect actual indent from first continuation line
            next_line = lines[run_line_idx + 1]
            if next_line && next_line.strip.length > 0
                actual_indent = next_line[/^(\s*)/, 1]
                content_indent_length = actual_indent.length
            else
                content_indent_length = run_indent.length + 2
            end
            i = run_line_idx + 1
            while i < lines.length
                line = lines[i]
                if line.strip.empty?
                    range << i
                    i += 1
                    next
                end
                line_indent = line[/^(\s*)/, 1] || ""
                break if line_indent.length < content_indent_length
                range << i
                i += 1
            end
        elsif lines[run_line_idx] =~ /^\s+run:\s+\S/
            # Single-line run: — only this line
            range << run_line_idx
        end

        range
    end

    private_class_method :extract_uses_string, :find_run_line,
                         :find_step_env_block, :find_env_block_end,
                         :find_run_block_range
end

if __FILE__ == $0
    # Simple self-test

    sample_workflow = [
        "name: CI\n",                                                      # 1
        "on: [push]\n",                                                    # 2
        "jobs:\n",                                                         # 3
        "  build:\n",                                                      # 4
        "    runs-on: ubuntu-latest\n",                                    # 5
        "    steps:\n",                                                    # 6
        "      - uses: actions/checkout@v4\n",                             # 7
        "      - uses: actions/setup-node@v4\n",                           # 8
        "        with:\n",                                                 # 9
        "          node-version: 18\n",                                    # 10
        "      - name: Greet\n",                                           # 11
        "        run: |\n",                                                # 12
        "          echo \"PR: ${{ github.event.pull_request.title }}\"\n", # 13
    ].join

    puts "=== Auto-Fix Self-Test ==="
    puts

    # Test 1: can_fix? detection
    pinnable = Finding.new(
        rule: "unpinned-actions",
        severity: :medium,
        file: "ci.yml",
        line: 7,
        code: "uses: actions/checkout@v4",
        message: "Action not SHA-pinned",
        fix: "Pin to SHA"
    )

    unfixable = Finding.new(
        rule: "missing-permissions",
        severity: :medium,
        file: "ci.yml",
        line: 1,
        code: "on: [push]",
        message: "No permissions block",
        fix: "Add permissions"
    )

    puts "can_fix?(unpinned-actions): #{AutoFix.can_fix?(pinnable)}"
    puts "can_fix?(missing-permissions): #{AutoFix.can_fix?(unfixable)}"
    puts

    # Test 2: SHA pinning (with a mock resolver)
    class MockShaResolver
        def resolve(_owner_action, _tag)
            "b4ffde65f46336ab88eb53be808477a3936bae11"
        end
    end

    result = AutoFix.apply(pinnable, sample_workflow, sha_resolver: MockShaResolver.new)
    has_sha = result.include?("b4ffde65f46336ab88eb53be808477a3936bae11")
    has_comment = result.include?("# v4")
    puts "SHA pin applied: #{has_sha}"
    puts "Tag comment preserved: #{has_comment}"
    puts

    # Test 3: persist-credentials fix (checkout without a with: block)
    persist_finding = Finding.new(
        rule: "missing-persist-credentials",
        severity: :high,
        file: "ci.yml",
        line: 7,
        code: "uses: actions/checkout@v4",
        message: "Missing persist-credentials: false",
        fix: "Add persist-credentials: false"
    )

    result2 = AutoFix.apply(persist_finding, sample_workflow)
    has_persist = result2.include?("persist-credentials: false")
    puts "persist-credentials added: #{has_persist}"
    puts

    # Test 4: shell injection fix
    injection_finding = Finding.new(
        rule: "shell-injection-expr",
        severity: :critical,
        file: "ci.yml",
        line: 13,
        code: 'echo "PR: ${{ github.event.pull_request.title }}"',
        message: "Shell injection risk",
        fix: "Move to env block"
    )

    result3 = AutoFix.apply(injection_finding, sample_workflow)
    has_env_block = result3.include?("env:")
    has_pr_title_var = result3.include?("PR_TITLE:")
    has_dollar_var = result3.include?("$PR_TITLE")
    # The expression should still be in the env: mapping, but NOT in the run block
    run_block_clean = result3.include?('echo "PR: $PR_TITLE"')
    puts "env: block added: #{has_env_block}"
    puts "PR_TITLE mapping: #{has_pr_title_var}"
    puts "$PR_TITLE substitution: #{has_dollar_var}"
    puts "Run block uses env var: #{run_block_clean}"
    puts

    # Test 5: persist-credentials with existing with: block
    sample_with_existing = [
        "name: CI\n",
        "on: [push]\n",
        "jobs:\n",
        "  build:\n",
        "    runs-on: ubuntu-latest\n",
        "    steps:\n",
        "      - uses: actions/checkout@v4\n",
        "        with:\n",
        "          ref: main\n",
    ].join

    persist_with_existing = Finding.new(
        rule: "missing-persist-credentials",
        severity: :high,
        file: "ci.yml",
        line: 7,
        code: "uses: actions/checkout@v4",
        message: "Missing persist-credentials: false",
        fix: "Add persist-credentials: false"
    )

    result4 = AutoFix.apply(persist_with_existing, sample_with_existing)
    has_persist_existing = result4.include?("persist-credentials: false")
    still_has_ref = result4.include?("ref: main")
    puts "persist-credentials added to existing with: #{has_persist_existing}"
    puts "Existing with: entries preserved: #{still_has_ref}"
    puts

    # Test 6: subpath action pinning (actions/cache/restore@v4)
    sample_subpath = [
        "name: CI\n",
        "on: [push]\n",
        "jobs:\n",
        "  build:\n",
        "    runs-on: ubuntu-latest\n",
        "    steps:\n",
        "      - uses: actions/cache/restore@v4\n",
    ].join

    subpath_finding = Finding.new(
        rule: "unpinned-actions",
        severity: :medium,
        file: "ci.yml",
        line: 7,
        code: "uses: actions/cache/restore@v4",
        message: "Action not SHA-pinned",
        fix: "Pin to SHA"
    )

    result5 = AutoFix.apply(subpath_finding, sample_subpath, sha_resolver: MockShaResolver.new)
    has_subpath_sha = result5.include?("actions/cache/restore@b4ffde65f46336ab88eb53be808477a3936bae11")
    has_subpath_comment = result5.include?("# v4")
    puts "Subpath action SHA pin: #{has_subpath_sha}"
    puts "Subpath tag comment: #{has_subpath_comment}"
    puts

    # Summary
    all_pass = has_sha && has_comment && has_persist && has_env_block &&
               has_pr_title_var && has_dollar_var && run_block_clean &&
               has_persist_existing && still_has_ref &&
               has_subpath_sha && has_subpath_comment
    puts all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED"
    exit(all_pass ? 0 : 1)
end

module Rules
  class Base
    def name
      raise NotImplementedError
    end

    def description
      raise NotImplementedError
    end

    def severity
      raise NotImplementedError
    end

    def check(workflow)
      raise NotImplementedError
    end

    private

    def finding(workflow, line:, code: nil, message: nil, fix: nil)
      Finding.new(
        rule: name,
        severity: severity,
        file: workflow.filename,
        line: line,
        code: code || workflow.line_content(line)&.strip,
        message: message || description,
        fix: fix
      )
    end
  end
end

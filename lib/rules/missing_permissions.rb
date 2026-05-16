module Rules
    class MissingPermissions < Base
        def name = "missing-permissions"
        def description = "No top-level permissions block"
        def severity = :medium

        def check(workflow)
            return [] if workflow.permissions(scope: :workflow)

            line = workflow.line_of(/^jobs:/) || 1
            [finding(workflow,
                line: line,
                message: "No top-level permissions block — jobs inherit broad default token permissions",
                fix: "Add permissions: contents: read at the workflow level"
            )]
        end
    end
end

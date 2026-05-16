require "minitest/autorun"
require_relative "../lib/finding"
require_relative "../lib/workflow"
require_relative "../lib/rule_engine"
require_relative "../lib/scanner"
require_relative "../lib/auto_fix"
require_relative "../lib/sha_resolver"

# Force-load all rules so they are available for individual rule tests
RuleEngine.new

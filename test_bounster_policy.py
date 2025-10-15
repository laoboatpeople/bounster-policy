"""
Unit tests for the Bounster Policy system.
"""

import unittest
from bounster_policy import (
    Policy,
    PolicyRule,
    PolicyAction,
    PolicyManager,
    PolicyResult,
    role_check,
    attribute_equals,
    attribute_in,
    combine_and,
    combine_or
)


class TestPolicyRule(unittest.TestCase):
    """Tests for PolicyRule class."""
    
    def test_rule_evaluation_true(self):
        """Test rule evaluates to True when condition is met."""
        rule = PolicyRule(
            name="test_rule",
            description="Test rule",
            condition=lambda ctx: ctx.get("value") == 42,
            action=PolicyAction.ALLOW
        )
        self.assertTrue(rule.evaluate({"value": 42}))
    
    def test_rule_evaluation_false(self):
        """Test rule evaluates to False when condition is not met."""
        rule = PolicyRule(
            name="test_rule",
            description="Test rule",
            condition=lambda ctx: ctx.get("value") == 42,
            action=PolicyAction.ALLOW
        )
        self.assertFalse(rule.evaluate({"value": 0}))
    
    def test_rule_evaluation_exception_handling(self):
        """Test rule handles exceptions gracefully."""
        rule = PolicyRule(
            name="test_rule",
            description="Test rule",
            condition=lambda ctx: ctx["missing_key"],  # Will raise KeyError
            action=PolicyAction.ALLOW
        )
        self.assertFalse(rule.evaluate({}))


class TestPolicy(unittest.TestCase):
    """Tests for Policy class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.policy = Policy("test_policy", "Test policy")
    
    def test_add_rule(self):
        """Test adding rules to policy."""
        rule = PolicyRule(
            name="rule1",
            description="Rule 1",
            condition=lambda ctx: True,
            action=PolicyAction.ALLOW
        )
        self.policy.add_rule(rule)
        self.assertEqual(len(self.policy.rules), 1)
    
    def test_remove_rule(self):
        """Test removing rules from policy."""
        rule = PolicyRule(
            name="rule1",
            description="Rule 1",
            condition=lambda ctx: True,
            action=PolicyAction.ALLOW
        )
        self.policy.add_rule(rule)
        self.assertTrue(self.policy.remove_rule("rule1"))
        self.assertEqual(len(self.policy.rules), 0)
    
    def test_remove_nonexistent_rule(self):
        """Test removing a rule that doesn't exist."""
        self.assertFalse(self.policy.remove_rule("nonexistent"))
    
    def test_evaluate_with_matching_rule(self):
        """Test policy evaluation with a matching rule."""
        rule = PolicyRule(
            name="allow_rule",
            description="Allow rule",
            condition=lambda ctx: ctx.get("allow", False),
            action=PolicyAction.ALLOW
        )
        self.policy.add_rule(rule)
        
        result = self.policy.evaluate({"allow": True})
        self.assertTrue(result.allowed)
        self.assertEqual(result.action, PolicyAction.ALLOW)
        self.assertIn("allow_rule", result.matched_rules)
    
    def test_evaluate_with_no_matching_rule(self):
        """Test policy evaluation with no matching rules."""
        rule = PolicyRule(
            name="allow_rule",
            description="Allow rule",
            condition=lambda ctx: ctx.get("allow", False),
            action=PolicyAction.ALLOW
        )
        self.policy.add_rule(rule)
        
        result = self.policy.evaluate({"allow": False})
        self.assertFalse(result.allowed)
        self.assertEqual(result.action, PolicyAction.DENY)
        self.assertEqual(len(result.matched_rules), 0)
    
    def test_rule_priority_order(self):
        """Test that rules are evaluated in priority order."""
        high_priority_rule = PolicyRule(
            name="high_priority",
            description="High priority",
            condition=lambda ctx: True,  # Always matches
            action=PolicyAction.ALLOW,
            priority=100
        )
        low_priority_rule = PolicyRule(
            name="low_priority",
            description="Low priority",
            condition=lambda ctx: True,  # Always matches
            action=PolicyAction.DENY,
            priority=1
        )
        
        self.policy.add_rule(low_priority_rule)
        self.policy.add_rule(high_priority_rule)
        
        result = self.policy.evaluate({})
        self.assertTrue(result.allowed)
        self.assertEqual(result.matched_rules, ["high_priority"])


class TestPolicyManager(unittest.TestCase):
    """Tests for PolicyManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = PolicyManager()
    
    def test_add_policy(self):
        """Test adding a policy to the manager."""
        policy = Policy("test_policy", "Test policy")
        self.manager.add_policy(policy)
        self.assertIsNotNone(self.manager.get_policy("test_policy"))
    
    def test_remove_policy(self):
        """Test removing a policy from the manager."""
        policy = Policy("test_policy", "Test policy")
        self.manager.add_policy(policy)
        self.assertTrue(self.manager.remove_policy("test_policy"))
        self.assertIsNone(self.manager.get_policy("test_policy"))
    
    def test_remove_nonexistent_policy(self):
        """Test removing a policy that doesn't exist."""
        self.assertFalse(self.manager.remove_policy("nonexistent"))
    
    def test_evaluate_existing_policy(self):
        """Test evaluating an existing policy."""
        policy = Policy("test_policy", "Test policy")
        policy.add_rule(PolicyRule(
            name="allow_rule",
            description="Allow rule",
            condition=lambda ctx: True,
            action=PolicyAction.ALLOW
        ))
        self.manager.add_policy(policy)
        
        result = self.manager.evaluate("test_policy", {})
        self.assertTrue(result.allowed)
    
    def test_evaluate_nonexistent_policy(self):
        """Test evaluating a policy that doesn't exist."""
        result = self.manager.evaluate("nonexistent", {})
        self.assertFalse(result.allowed)
        self.assertIn("not found", result.reason)
    
    def test_evaluate_all_policies(self):
        """Test evaluating all policies."""
        policy1 = Policy("policy1", "Policy 1")
        policy1.add_rule(PolicyRule(
            name="allow",
            description="Allow",
            condition=lambda ctx: True,
            action=PolicyAction.ALLOW
        ))
        
        policy2 = Policy("policy2", "Policy 2")
        policy2.add_rule(PolicyRule(
            name="deny",
            description="Deny",
            condition=lambda ctx: False,
            action=PolicyAction.ALLOW
        ))
        
        self.manager.add_policy(policy1)
        self.manager.add_policy(policy2)
        
        results = self.manager.evaluate_all({})
        self.assertEqual(len(results), 2)
        self.assertTrue(results["policy1"].allowed)
        self.assertFalse(results["policy2"].allowed)


class TestConditionHelpers(unittest.TestCase):
    """Tests for condition helper functions."""
    
    def test_role_check(self):
        """Test role_check condition helper."""
        condition = role_check("admin")
        self.assertTrue(condition({"roles": ["admin", "user"]}))
        self.assertFalse(condition({"roles": ["user"]}))
        self.assertFalse(condition({}))
    
    def test_attribute_equals(self):
        """Test attribute_equals condition helper."""
        condition = attribute_equals("status", "active")
        self.assertTrue(condition({"status": "active"}))
        self.assertFalse(condition({"status": "inactive"}))
        self.assertFalse(condition({}))
    
    def test_attribute_in(self):
        """Test attribute_in condition helper."""
        condition = attribute_in("level", [1, 2, 3])
        self.assertTrue(condition({"level": 2}))
        self.assertFalse(condition({"level": 5}))
        self.assertFalse(condition({}))
    
    def test_combine_and(self):
        """Test combine_and condition helper."""
        condition = combine_and(
            attribute_equals("status", "active"),
            role_check("admin")
        )
        self.assertTrue(condition({"status": "active", "roles": ["admin"]}))
        self.assertFalse(condition({"status": "active", "roles": ["user"]}))
        self.assertFalse(condition({"status": "inactive", "roles": ["admin"]}))
    
    def test_combine_or(self):
        """Test combine_or condition helper."""
        condition = combine_or(
            attribute_equals("status", "active"),
            role_check("admin")
        )
        self.assertTrue(condition({"status": "active", "roles": ["user"]}))
        self.assertTrue(condition({"status": "inactive", "roles": ["admin"]}))
        self.assertTrue(condition({"status": "active", "roles": ["admin"]}))
        self.assertFalse(condition({"status": "inactive", "roles": ["user"]}))


class TestPolicyResult(unittest.TestCase):
    """Tests for PolicyResult class."""
    
    def test_policy_result_creation(self):
        """Test creating a PolicyResult."""
        result = PolicyResult(
            allowed=True,
            action=PolicyAction.ALLOW,
            matched_rules=["rule1"],
            reason="Test reason"
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.action, PolicyAction.ALLOW)
        self.assertEqual(result.matched_rules, ["rule1"])
        self.assertEqual(result.reason, "Test reason")


if __name__ == "__main__":
    unittest.main()

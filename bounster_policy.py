"""
Bounster Policy - A simple and flexible policy-based access control system.

This module provides a framework for defining and enforcing access control policies
based on rules, roles, and permissions.
"""

from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class PolicyAction(Enum):
    """Enum representing possible policy actions."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


@dataclass
class PolicyRule:
    """Represents a single policy rule."""
    name: str
    description: str
    condition: Callable[[Dict[str, Any]], bool]
    action: PolicyAction
    priority: int = 0
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate the rule condition against the given context."""
        try:
            return self.condition(context)
        except Exception:
            return False


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""
    allowed: bool
    action: PolicyAction
    matched_rules: List[str] = field(default_factory=list)
    reason: Optional[str] = None


class Policy:
    """Main policy class that manages and evaluates rules."""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.rules: List[PolicyRule] = []
        self.default_action = PolicyAction.DENY
    
    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule to the policy."""
        self.rules.append(rule)
        # Sort rules by priority (higher priority first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule from the policy by name."""
        initial_length = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        return len(self.rules) < initial_length
    
    def evaluate(self, context: Dict[str, Any]) -> PolicyResult:
        """
        Evaluate the policy against the given context.
        
        Args:
            context: Dictionary containing the context for evaluation
            
        Returns:
            PolicyResult indicating whether access is allowed and why
        """
        matched_rules = []
        final_action = self.default_action
        
        for rule in self.rules:
            if rule.evaluate(context):
                matched_rules.append(rule.name)
                final_action = rule.action
                # First matching rule wins (since rules are sorted by priority)
                break
        
        allowed = final_action == PolicyAction.ALLOW
        reason = f"Matched rules: {', '.join(matched_rules)}" if matched_rules else "No rules matched, default action applied"
        
        return PolicyResult(
            allowed=allowed,
            action=final_action,
            matched_rules=matched_rules,
            reason=reason
        )


class PolicyManager:
    """Manages multiple policies and provides a unified interface."""
    
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
    
    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the manager."""
        self.policies[policy.name] = policy
    
    def remove_policy(self, policy_name: str) -> bool:
        """Remove a policy from the manager."""
        if policy_name in self.policies:
            del self.policies[policy_name]
            return True
        return False
    
    def get_policy(self, policy_name: str) -> Optional[Policy]:
        """Get a policy by name."""
        return self.policies.get(policy_name)
    
    def evaluate(self, policy_name: str, context: Dict[str, Any]) -> PolicyResult:
        """
        Evaluate a specific policy.
        
        Args:
            policy_name: Name of the policy to evaluate
            context: Context for evaluation
            
        Returns:
            PolicyResult
        """
        policy = self.get_policy(policy_name)
        if not policy:
            return PolicyResult(
                allowed=False,
                action=PolicyAction.DENY,
                reason=f"Policy '{policy_name}' not found"
            )
        
        return policy.evaluate(context)
    
    def evaluate_all(self, context: Dict[str, Any]) -> Dict[str, PolicyResult]:
        """
        Evaluate all policies.
        
        Args:
            context: Context for evaluation
            
        Returns:
            Dictionary mapping policy names to their results
        """
        return {
            name: policy.evaluate(context)
            for name, policy in self.policies.items()
        }


# Convenience functions for common rule conditions
def role_check(required_role: str) -> Callable[[Dict[str, Any]], bool]:
    """Create a condition function that checks for a required role."""
    def condition(context: Dict[str, Any]) -> bool:
        user_roles = context.get("roles", [])
        return required_role in user_roles
    return condition


def attribute_equals(key: str, value: Any) -> Callable[[Dict[str, Any]], bool]:
    """Create a condition function that checks if an attribute equals a value."""
    def condition(context: Dict[str, Any]) -> bool:
        return context.get(key) == value
    return condition


def attribute_in(key: str, values: List[Any]) -> Callable[[Dict[str, Any]], bool]:
    """Create a condition function that checks if an attribute is in a list of values."""
    def condition(context: Dict[str, Any]) -> bool:
        return context.get(key) in values
    return condition


def combine_and(*conditions: Callable[[Dict[str, Any]], bool]) -> Callable[[Dict[str, Any]], bool]:
    """Combine multiple conditions with AND logic."""
    def condition(context: Dict[str, Any]) -> bool:
        return all(cond(context) for cond in conditions)
    return condition


def combine_or(*conditions: Callable[[Dict[str, Any]], bool]) -> Callable[[Dict[str, Any]], bool]:
    """Combine multiple conditions with OR logic."""
    def condition(context: Dict[str, Any]) -> bool:
        return any(cond(context) for cond in conditions)
    return condition

"""
Example configuration for Bounster Policy.

This file demonstrates how to configure policies using a structured approach,
which can be easily loaded from configuration files or environment variables.
"""

from typing import Dict, Any, List
from bounster_policy import (
    Policy,
    PolicyRule,
    PolicyAction,
    PolicyManager,
    role_check,
    attribute_equals,
    attribute_in,
    combine_and,
    combine_or
)


class PolicyConfig:
    """Helper class for building policies from configuration."""
    
    @staticmethod
    def create_role_based_policy(
        policy_name: str,
        allowed_roles: List[str],
        description: str = ""
    ) -> Policy:
        """
        Create a simple role-based policy.
        
        Args:
            policy_name: Name of the policy
            allowed_roles: List of roles that are allowed
            description: Policy description
            
        Returns:
            Configured Policy
        """
        policy = Policy(policy_name, description)
        
        for i, role in enumerate(allowed_roles):
            policy.add_rule(PolicyRule(
                name=f"{role}_access",
                description=f"Allow access for {role} role",
                condition=role_check(role),
                action=PolicyAction.ALLOW,
                priority=100 - i  # Earlier roles have higher priority
            ))
        
        return policy
    
    @staticmethod
    def create_attribute_based_policy(
        policy_name: str,
        attribute_rules: Dict[str, Any],
        description: str = ""
    ) -> Policy:
        """
        Create an attribute-based policy.
        
        Args:
            policy_name: Name of the policy
            attribute_rules: Dictionary of attribute conditions
            description: Policy description
            
        Returns:
            Configured Policy
        """
        policy = Policy(policy_name, description)
        
        for rule_name, rule_config in attribute_rules.items():
            attr_key = rule_config.get("attribute")
            attr_value = rule_config.get("value")
            action = PolicyAction[rule_config.get("action", "ALLOW")]
            priority = rule_config.get("priority", 50)
            
            policy.add_rule(PolicyRule(
                name=rule_name,
                description=rule_config.get("description", ""),
                condition=attribute_equals(attr_key, attr_value),
                action=action,
                priority=priority
            ))
        
        return policy


# Example: Pre-configured policies for common use cases
def get_default_api_policies() -> PolicyManager:
    """
    Get a PolicyManager with default API access policies.
    
    Returns:
        PolicyManager with configured policies
    """
    manager = PolicyManager()
    
    # Read access policy
    read_policy = PolicyConfig.create_role_based_policy(
        "api_read",
        ["admin", "editor", "viewer", "user"],
        "Controls read access to API resources"
    )
    manager.add_policy(read_policy)
    
    # Write access policy
    write_policy = PolicyConfig.create_role_based_policy(
        "api_write",
        ["admin", "editor"],
        "Controls write access to API resources"
    )
    manager.add_policy(write_policy)
    
    # Delete access policy
    delete_policy = PolicyConfig.create_role_based_policy(
        "api_delete",
        ["admin"],
        "Controls delete access to API resources"
    )
    manager.add_policy(delete_policy)
    
    # Admin access policy with additional checks
    admin_policy = Policy("admin_panel", "Controls access to admin panel")
    admin_policy.add_rule(PolicyRule(
        name="admin_authenticated",
        description="Admin must be authenticated and have admin role",
        condition=combine_and(
            role_check("admin"),
            attribute_equals("authenticated", True),
            attribute_equals("mfa_verified", True)
        ),
        action=PolicyAction.ALLOW,
        priority=100
    ))
    manager.add_policy(admin_policy)
    
    return manager


# Example: Configuration-driven policy setup
POLICY_CONFIGURATION = {
    "rate_limiting": {
        "description": "Rate limiting policy",
        "rules": {
            "premium_user": {
                "attribute": "subscription_tier",
                "value": "premium",
                "action": "ALLOW",
                "priority": 100,
                "description": "Premium users have unlimited access"
            },
            "standard_user": {
                "attribute": "subscription_tier",
                "value": "standard",
                "action": "ALLOW",
                "priority": 50,
                "description": "Standard users have limited access"
            }
        }
    }
}


def load_policies_from_config(config: Dict[str, Any]) -> PolicyManager:
    """
    Load policies from a configuration dictionary.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        PolicyManager with loaded policies
    """
    manager = PolicyManager()
    
    for policy_name, policy_config in config.items():
        description = policy_config.get("description", "")
        rules = policy_config.get("rules", {})
        
        policy = PolicyConfig.create_attribute_based_policy(
            policy_name,
            rules,
            description
        )
        manager.add_policy(policy)
    
    return manager


if __name__ == "__main__":
    # Example 1: Using pre-configured policies
    print("=== Default API Policies ===")
    api_manager = get_default_api_policies()
    
    admin_context = {
        "roles": ["admin"],
        "authenticated": True,
        "mfa_verified": True
    }
    
    results = api_manager.evaluate_all(admin_context)
    for policy_name, result in results.items():
        print(f"{policy_name}: {result.allowed} - {result.reason}")
    print()
    
    # Example 2: Loading from configuration
    print("=== Configuration-driven Policies ===")
    config_manager = load_policies_from_config(POLICY_CONFIGURATION)
    
    premium_context = {"subscription_tier": "premium"}
    standard_context = {"subscription_tier": "standard"}
    free_context = {"subscription_tier": "free"}
    
    for ctx_name, ctx in [("Premium", premium_context), 
                           ("Standard", standard_context), 
                           ("Free", free_context)]:
        result = config_manager.evaluate("rate_limiting", ctx)
        print(f"{ctx_name}: {result.allowed} - {result.reason}")

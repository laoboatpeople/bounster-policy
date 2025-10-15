"""
Example usage of the Bounster Policy system.

This file demonstrates various ways to use the policy framework
for access control and validation.
"""

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


def example_basic_policy():
    """Example of a basic policy with simple rules."""
    print("=== Basic Policy Example ===")
    
    # Create a policy
    policy = Policy("api_access", "Controls access to API endpoints")
    
    # Add rules
    policy.add_rule(PolicyRule(
        name="admin_access",
        description="Admins have full access",
        condition=role_check("admin"),
        action=PolicyAction.ALLOW,
        priority=100
    ))
    
    policy.add_rule(PolicyRule(
        name="authenticated_user",
        description="Authenticated users have basic access",
        condition=lambda ctx: ctx.get("authenticated", False),
        action=PolicyAction.ALLOW,
        priority=50
    ))
    
    # Evaluate for different contexts
    admin_context = {"roles": ["admin"], "authenticated": True}
    user_context = {"roles": ["user"], "authenticated": True}
    guest_context = {"authenticated": False}
    
    print(f"Admin access: {policy.evaluate(admin_context)}")
    print(f"User access: {policy.evaluate(user_context)}")
    print(f"Guest access: {policy.evaluate(guest_context)}")
    print()


def example_complex_conditions():
    """Example using complex conditions with AND/OR logic."""
    print("=== Complex Conditions Example ===")
    
    policy = Policy("resource_access", "Controls access to specific resources")
    
    # Rule with combined conditions
    policy.add_rule(PolicyRule(
        name="owner_or_admin",
        description="Resource owner or admin can access",
        condition=combine_or(
            attribute_equals("is_owner", True),
            role_check("admin")
        ),
        action=PolicyAction.ALLOW,
        priority=100
    ))
    
    policy.add_rule(PolicyRule(
        name="team_member_with_permission",
        description="Team members with read permission can access",
        condition=combine_and(
            attribute_in("team", ["engineering", "product"]),
            attribute_equals("has_read_permission", True)
        ),
        action=PolicyAction.ALLOW,
        priority=50
    ))
    
    # Test different scenarios
    contexts = [
        {"is_owner": True, "roles": []},
        {"roles": ["admin"], "is_owner": False},
        {"team": "engineering", "has_read_permission": True},
        {"team": "marketing", "has_read_permission": True},
    ]
    
    for i, ctx in enumerate(contexts, 1):
        result = policy.evaluate(ctx)
        print(f"Context {i}: {ctx}")
        print(f"Result: {result}")
        print()


def example_policy_manager():
    """Example using PolicyManager to manage multiple policies."""
    print("=== Policy Manager Example ===")
    
    manager = PolicyManager()
    
    # Create and add multiple policies
    read_policy = Policy("read_access", "Read access control")
    read_policy.add_rule(PolicyRule(
        name="authenticated_read",
        description="Authenticated users can read",
        condition=lambda ctx: ctx.get("authenticated", False),
        action=PolicyAction.ALLOW
    ))
    
    write_policy = Policy("write_access", "Write access control")
    write_policy.add_rule(PolicyRule(
        name="admin_write",
        description="Only admins can write",
        condition=role_check("admin"),
        action=PolicyAction.ALLOW,
        priority=100
    ))
    write_policy.add_rule(PolicyRule(
        name="editor_write",
        description="Editors can write",
        condition=role_check("editor"),
        action=PolicyAction.ALLOW,
        priority=50
    ))
    
    manager.add_policy(read_policy)
    manager.add_policy(write_policy)
    
    # Evaluate different contexts
    admin_ctx = {"roles": ["admin"], "authenticated": True}
    editor_ctx = {"roles": ["editor"], "authenticated": True}
    user_ctx = {"roles": ["user"], "authenticated": True}
    
    print("Admin context:")
    print(f"  Read: {manager.evaluate('read_access', admin_ctx)}")
    print(f"  Write: {manager.evaluate('write_access', admin_ctx)}")
    print()
    
    print("Editor context:")
    print(f"  Read: {manager.evaluate('read_access', editor_ctx)}")
    print(f"  Write: {manager.evaluate('write_access', editor_ctx)}")
    print()
    
    print("User context:")
    print(f"  Read: {manager.evaluate('read_access', user_ctx)}")
    print(f"  Write: {manager.evaluate('write_access', user_ctx)}")
    print()


def example_priority_rules():
    """Example showing how rule priority affects evaluation."""
    print("=== Priority Rules Example ===")
    
    policy = Policy("priority_demo", "Demonstrates rule priority")
    
    # Add rules with different priorities
    policy.add_rule(PolicyRule(
        name="low_priority_deny",
        description="Low priority deny rule",
        condition=lambda ctx: True,  # Always matches
        action=PolicyAction.DENY,
        priority=1
    ))
    
    policy.add_rule(PolicyRule(
        name="high_priority_allow",
        description="High priority allow for admins",
        condition=role_check("admin"),
        action=PolicyAction.ALLOW,
        priority=100
    ))
    
    # Test with admin (high priority rule should match first)
    admin_ctx = {"roles": ["admin"]}
    result = policy.evaluate(admin_ctx)
    print(f"Admin context: {result}")
    print(f"Matched rules: {result.matched_rules}")
    print()
    
    # Test with non-admin (low priority rule should match)
    user_ctx = {"roles": ["user"]}
    result = policy.evaluate(user_ctx)
    print(f"User context: {result}")
    print(f"Matched rules: {result.matched_rules}")
    print()


if __name__ == "__main__":
    example_basic_policy()
    example_complex_conditions()
    example_policy_manager()
    example_priority_rules()

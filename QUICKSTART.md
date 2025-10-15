# Bounster Policy - Quick Start Guide

Get started with Bounster Policy in 5 minutes!

## Installation

```bash
# Option 1: Install from source
git clone https://github.com/laoboatpeople/bounster-policy.git
cd bounster-policy
pip install -e .

# Option 2: Copy the module directly
# Just copy bounster_policy.py to your project
```

## Your First Policy

```python
from bounster_policy import Policy, PolicyRule, PolicyAction, role_check

# Create a policy
policy = Policy("api_access", "Controls API access")

# Add a rule for admins
policy.add_rule(PolicyRule(
    name="admin_full_access",
    description="Admins have full access",
    condition=role_check("admin"),
    action=PolicyAction.ALLOW,
    priority=100
))

# Add a rule for regular users
policy.add_rule(PolicyRule(
    name="user_basic_access",
    description="Users have basic access",
    condition=lambda ctx: ctx.get("authenticated", False),
    action=PolicyAction.ALLOW,
    priority=50
))

# Test it!
admin_result = policy.evaluate({"roles": ["admin"], "authenticated": True})
print(f"Admin allowed: {admin_result.allowed}")  # True

user_result = policy.evaluate({"authenticated": True})
print(f"User allowed: {user_result.allowed}")  # True

guest_result = policy.evaluate({"authenticated": False})
print(f"Guest allowed: {guest_result.allowed}")  # False
```

## Common Patterns

### 1. Role-Based Access Control (RBAC)

```python
from bounster_policy import Policy, PolicyRule, PolicyAction, role_check

policy = Policy("resource_access")
policy.add_rule(PolicyRule(
    name="admin",
    condition=role_check("admin"),
    action=PolicyAction.ALLOW
))
```

### 2. Attribute-Based Access Control (ABAC)

```python
from bounster_policy import attribute_equals, combine_and

policy.add_rule(PolicyRule(
    name="owner_only",
    condition=combine_and(
        attribute_equals("is_owner", True),
        attribute_equals("authenticated", True)
    ),
    action=PolicyAction.ALLOW
))
```

### 3. Complex Conditions

```python
from bounster_policy import combine_or, role_check, attribute_equals

# Allow if user is owner OR admin
policy.add_rule(PolicyRule(
    name="owner_or_admin",
    condition=combine_or(
        attribute_equals("is_owner", True),
        role_check("admin")
    ),
    action=PolicyAction.ALLOW
))
```

### 4. Managing Multiple Policies

```python
from bounster_policy import PolicyManager

manager = PolicyManager()
manager.add_policy(read_policy)
manager.add_policy(write_policy)

# Check a specific policy
can_read = manager.evaluate("read_policy", context)

# Check all policies
all_results = manager.evaluate_all(context)
```

## Real-World Example: API Authorization

```python
from bounster_policy import (
    Policy, PolicyRule, PolicyAction, PolicyManager,
    role_check, attribute_equals, combine_and
)

# Create policies for different operations
manager = PolicyManager()

# Read policy - most users can read
read_policy = Policy("read")
read_policy.add_rule(PolicyRule(
    name="authenticated_read",
    condition=attribute_equals("authenticated", True),
    action=PolicyAction.ALLOW
))
manager.add_policy(read_policy)

# Write policy - only editors and admins
write_policy = Policy("write")
write_policy.add_rule(PolicyRule(
    name="editor_write",
    condition=combine_and(
        attribute_equals("authenticated", True),
        role_check("editor")
    ),
    action=PolicyAction.ALLOW,
    priority=100
))
write_policy.add_rule(PolicyRule(
    name="admin_write",
    condition=role_check("admin"),
    action=PolicyAction.ALLOW,
    priority=100
))
manager.add_policy(write_policy)

# Use in your API
def handle_request(user, operation, resource):
    context = {
        "authenticated": user.is_authenticated,
        "roles": user.roles,
        "is_owner": resource.owner_id == user.id
    }
    
    result = manager.evaluate(operation, context)
    
    if result.allowed:
        # Process the request
        return process_request(resource)
    else:
        # Return 403 Forbidden
        return {"error": "Access denied", "reason": result.reason}
```

## Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Check out [examples.py](examples.py) for more examples
3. Look at [config_example.py](config_example.py) for configuration patterns
4. Run the tests: `python -m unittest test_bounster_policy`

## Common Use Cases

- **API Access Control**: Control who can read, write, or delete resources
- **Feature Flags**: Enable/disable features for different user groups
- **Rate Limiting**: Apply different rate limits based on user tier
- **Multi-tenant Systems**: Isolate data between tenants
- **Content Moderation**: Control what content users can see or post
- **Admin Panels**: Restrict administrative functions

## Getting Help

- Read the [API Reference](README.md#api-reference) in the main README
- Check the [examples](examples.py) for common patterns
- Look at the [tests](test_bounster_policy.py) for edge cases
- Open an issue on GitHub for bugs or questions

Happy policy building! 🚀

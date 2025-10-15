# Bounster Policy

A simple and flexible policy-based access control system for Python applications.

## Overview

Bounster Policy provides a framework for defining and enforcing access control policies based on rules, roles, and permissions. It allows you to create complex authorization logic with a clean, declarative API.

## Features

- **Rule-based access control**: Define policies using flexible rules with priorities
- **Role-based access**: Built-in support for role-based authorization
- **Attribute-based access**: Check any attributes in the context
- **Composable conditions**: Combine multiple conditions with AND/OR logic
- **Policy Manager**: Manage multiple policies in a unified interface
- **Priority system**: Control rule evaluation order with priorities
- **Type-safe**: Uses Python dataclasses and type hints

## Installation

Simply copy the `bounster_policy.py` file to your project, or add it to your Python path.

```bash
# No external dependencies required - uses only Python standard library
python bounster_policy.py
```

## Quick Start

### Basic Usage

```python
from bounster_policy import Policy, PolicyRule, PolicyAction, role_check

# Create a policy
policy = Policy("api_access", "Controls API access")

# Add a rule
policy.add_rule(PolicyRule(
    name="admin_access",
    description="Admins have full access",
    condition=role_check("admin"),
    action=PolicyAction.ALLOW,
    priority=100
))

# Evaluate the policy
context = {"roles": ["admin"], "authenticated": True}
result = policy.evaluate(context)

print(f"Access allowed: {result.allowed}")
print(f"Reason: {result.reason}")
```

### Using Policy Manager

```python
from bounster_policy import PolicyManager

manager = PolicyManager()
manager.add_policy(read_policy)
manager.add_policy(write_policy)

# Evaluate a specific policy
result = manager.evaluate("read_policy", context)

# Evaluate all policies
results = manager.evaluate_all(context)
```

## Core Concepts

### Policies

A `Policy` is a collection of rules that are evaluated to determine if access should be granted. Each policy has:
- A unique name
- A description
- A list of rules
- A default action (DENY by default)

### Rules

A `PolicyRule` defines a condition and an action. Rules have:
- **name**: Unique identifier for the rule
- **description**: Human-readable description
- **condition**: A function that takes a context and returns True/False
- **action**: ALLOW, DENY, or CHALLENGE
- **priority**: Higher priority rules are evaluated first

### Context

The context is a dictionary containing all the information needed to evaluate policies, such as:
- User roles
- Authentication status
- Resource attributes
- Request metadata

## Advanced Features

### Condition Helpers

Built-in helpers for common conditions:

```python
from bounster_policy import (
    role_check,           # Check if a role exists
    attribute_equals,     # Check if attribute equals value
    attribute_in,         # Check if attribute is in a list
    combine_and,          # Combine conditions with AND
    combine_or            # Combine conditions with OR
)

# Example: User must be authenticated AND have admin role
condition = combine_and(
    attribute_equals("authenticated", True),
    role_check("admin")
)
```

### Priority System

Rules are evaluated in priority order (highest first). The first matching rule determines the result:

```python
# High priority rule - evaluated first
policy.add_rule(PolicyRule(
    name="admin_override",
    condition=role_check("admin"),
    action=PolicyAction.ALLOW,
    priority=100
))

# Low priority rule - evaluated if high priority doesn't match
policy.add_rule(PolicyRule(
    name="default_deny",
    condition=lambda ctx: True,
    action=PolicyAction.DENY,
    priority=1
))
```

## Examples

See the `examples.py` file for comprehensive examples including:
- Basic policy usage
- Complex conditions with AND/OR logic
- Policy manager usage
- Priority rule examples

See `config_example.py` for:
- Configuration-driven policy setup
- Pre-configured policies for common use cases
- Loading policies from configuration

## Testing

Run the unit tests:

```bash
python test_bounster_policy.py
```

Or with verbose output:

```bash
python -m unittest test_bounster_policy -v
```

## Use Cases

Bounster Policy is ideal for:
- API access control
- Resource authorization
- Feature flags and permissions
- Rate limiting policies
- Multi-tenant access control
- Content moderation policies

## API Reference

### Policy

```python
Policy(name: str, description: str = "")
```
- `add_rule(rule: PolicyRule)`: Add a rule to the policy
- `remove_rule(rule_name: str)`: Remove a rule by name
- `evaluate(context: Dict[str, Any])`: Evaluate the policy

### PolicyRule

```python
PolicyRule(
    name: str,
    description: str,
    condition: Callable[[Dict[str, Any]], bool],
    action: PolicyAction,
    priority: int = 0
)
```

### PolicyManager

```python
PolicyManager()
```
- `add_policy(policy: Policy)`: Add a policy
- `remove_policy(policy_name: str)`: Remove a policy
- `get_policy(policy_name: str)`: Get a policy by name
- `evaluate(policy_name: str, context: Dict[str, Any])`: Evaluate a specific policy
- `evaluate_all(context: Dict[str, Any])`: Evaluate all policies

### PolicyAction

Enum with values:
- `ALLOW`: Grant access
- `DENY`: Deny access
- `CHALLENGE`: Require additional verification

## License

This project is released into the public domain. Feel free to use, modify, and distribute as needed.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

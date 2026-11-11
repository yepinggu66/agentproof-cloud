"""The policy layer must fail closed in every uncertain case."""

from __future__ import annotations

import pytest
import yaml

from agentproof.core.policy import PolicyError, load_policy
from agentproof.core.receipt import Decision


def _write_policy(tmp_path, data) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


BASIC = {
    "version": 1,
    "subject": "acme-support-agent",
    "capabilities": [
        {"name": "kb.search", "description": "Read-only KB search"},
        {"name": "order.refund", "description": "Refund an order"},
    ],
    "rules": [
        {
            "id": "allow-kb-search",
            "action": "kb.search",
            "effect": "allow",
            "reason": "Read-only access is pre-approved",
            "conditions": {"max_input_bytes": 65536},
        },
        {
            "id": "allow-refund-small",
            "action": "order.refund",
            "effect": "allow",
            "reason": "Refunds under the limit are pre-approved",
            "conditions": {"max_input_bytes": 4096},
        },
        {
            "id": "deny-db-write",
            "action": "db.write",
            "effect": "deny",
            "reason": "Writes to the customer database are not permitted",
        },
        {
            "id": "deny-default",
            "action": "*",
            "effect": "deny",
            "reason": "Default deny",
        },
    ],
}


@pytest.fixture
def policy(tmp_path):
    return load_policy(_write_policy(tmp_path, BASIC))


# ----------------------------------------------------------------------
# the core behaviour
# ----------------------------------------------------------------------
def test_declared_action_is_allowed(policy):
    evaluation = policy.evaluate("kb.search", inputs={"q": "refund"})
    assert evaluation.decision is Decision.ALLOW
    assert evaluation.permitted
    assert evaluation.rule_id == "allow-kb-search"


def test_undeclared_action_is_denied(policy):
    evaluation = policy.evaluate("db.write", inputs={})
    assert evaluation.decision is Decision.DENY
    assert not evaluation.permitted


def test_action_matching_no_rule_is_denied(policy, tmp_path):
    """No matching rule must never mean 'allow'."""
    no_default = load_policy(
        _write_policy(
            tmp_path,
            {
                "version": 1,
                "subject": "s",
                "capabilities": [],
                "rules": [{"id": "only-one", "action": "kb.search", "effect": "allow"}],
            },
        )
    )
    evaluation = no_default.evaluate("something.else", inputs={})
    assert evaluation.decision is Decision.DENY
    assert "no policy rule matches" in evaluation.reason


def test_capability_not_declared_is_denied(tmp_path):
    """An action the subject was never granted must be refused."""
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [{"name": "kb.search"}],
        "rules": [
            {"id": "allow-anything", "action": "*", "effect": "allow"},
        ],
    }
    policy = load_policy(_write_policy(tmp_path, data))

    evaluation = policy.evaluate("db.drop_all", inputs={})
    assert evaluation.decision is Decision.DENY
    assert "never declared" in evaluation.reason


def test_oversized_input_is_denied(policy):
    evaluation = policy.evaluate("kb.search", inputs={"q": "x" * 100000})
    assert evaluation.decision is Decision.DENY
    assert "exceeding" in evaluation.reason


def test_missing_scope_is_denied(tmp_path):
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [{"name": "kb.search"}],
        "rules": [
            {
                "id": "allow-scoped",
                "action": "kb.search",
                "effect": "allow",
                "conditions": {"required_scopes": ["kb:read"]},
            }
        ],
    }
    policy = load_policy(_write_policy(tmp_path, data))

    denied = policy.evaluate("kb.search", inputs={}, context={"scopes": []})
    assert denied.decision is Decision.DENY
    assert "missing required scope" in denied.reason

    allowed = policy.evaluate(
        "kb.search", inputs={}, context={"scopes": ["kb:read", "kb:write"]}
    )
    assert allowed.decision is Decision.ALLOW


def test_explicit_halt_rule_halts(tmp_path):
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [],
        "rules": [
            {"id": "halt-ambiguous", "action": "kb.*", "effect": "halt", "reason": "needs review"},
        ],
    }
    policy = load_policy(_write_policy(tmp_path, data))
    evaluation = policy.evaluate("kb.search", inputs={})
    assert evaluation.decision is Decision.HALT
    assert not evaluation.permitted


def test_unknown_effect_halts(tmp_path):
    """An unclear rule intent must not be read as permission."""
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [],
        "rules": [{"id": "weird", "action": "x", "effect": "maybe"}],
    }
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    # The loader rejects it outright, which is the stronger guarantee.
    with pytest.raises(PolicyError):
        load_policy(str(path))


def test_raising_precondition_check_halts(tmp_path):
    """A precondition that cannot be evaluated must not permit the action."""
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [{"name": "kb.search"}],
        "rules": [
            {"id": "allow-checked", "action": "kb.search", "effect": "allow"},
        ],
    }
    policy = load_policy(_write_policy(tmp_path, data)).with_check(
        "allow-checked", lambda inputs, context: 1 / 0
    )

    evaluation = policy.evaluate("kb.search", inputs={})
    assert evaluation.decision is Decision.HALT
    assert "could not be established" in evaluation.reason


def test_failing_precondition_check_denies(tmp_path):
    data = {
        "version": 1,
        "subject": "s",
        "capabilities": [{"name": "kb.search"}],
        "rules": [
            {"id": "allow-checked", "action": "kb.search", "effect": "allow"},
        ],
    }
    policy = load_policy(_write_policy(tmp_path, data)).with_check(
        "allow-checked", lambda inputs, context: False
    )
    assert policy.evaluate("kb.search", inputs={}).decision is Decision.DENY


def test_callable_check_in_yaml_is_rejected(tmp_path):
    """A callable cannot be loaded from a file; that must be an error."""
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\n"
        "subject: s\n"
        "rules:\n"
        "  - id: r\n"
        "    action: a\n"
        "    effect: allow\n"
        "    conditions:\n"
        "      check: some_function\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="callable"):
        load_policy(str(path))


# ----------------------------------------------------------------------
# malformed policies
# ----------------------------------------------------------------------
def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(str(tmp_path / "nope.yaml"))


def test_invalid_yaml_raises(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\n  bad indent: [", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(str(path))


def test_missing_rules_raises(tmp_path):
    with pytest.raises(PolicyError, match="rules"):
        load_policy(_write_policy(tmp_path, {"version": 1, "subject": "s"}))


def test_duplicate_rule_id_raises(tmp_path):
    data = {
        "version": 1,
        "subject": "s",
        "rules": [
            {"id": "dup", "action": "a", "effect": "allow"},
            {"id": "dup", "action": "b", "effect": "deny"},
        ],
    }
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy(_write_policy(tmp_path, data))


def test_missing_version_raises(tmp_path):
    with pytest.raises(PolicyError, match="version"):
        load_policy(
            _write_policy(tmp_path, {"subject": "s", "rules": [{"id": "x", "action": "a", "effect": "allow"}]})
        )


def test_policy_digest_is_stable_across_loads(tmp_path):
    first = load_policy(_write_policy(tmp_path, BASIC))
    second = load_policy(_write_policy(tmp_path, BASIC))
    assert first.policy_digest == second.policy_digest


def test_policy_digest_changes_with_content(tmp_path):
    first = load_policy(_write_policy(tmp_path, BASIC))
    changed = dict(BASIC)
    changed["rules"] = [dict(BASIC["rules"][0])]
    changed["rules"][0]["reason"] = "different reason"
    second = load_policy(_write_policy(tmp_path, changed))
    assert first.policy_digest != second.policy_digest

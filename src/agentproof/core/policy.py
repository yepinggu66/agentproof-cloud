"""Policy evaluation — the fail-closed gate.

The rule this module exists to enforce:

    A permission is the *result* of a positive match against an explicit
    rule, with every precondition satisfied. There is no default-allow path.

Concretely, every one of these returns a non-permitted decision:

* no rule matches the action
* a rule matches but a precondition cannot be evaluated (missing capability,
  unreachable dependency, ambiguous argument)
* the policy file itself is malformed
* the requested capability was never declared

The last point is the one that matters most in practice. If an agent asks for
a tool it was never granted, the answer is DENY — not "let it try and see".
Granting by default is how agents end up doing things their operator never
approved.

Policy files are YAML::

    version: 1
    subject: "acme-support-agent"
    capabilities:
      - name: kb.search
        description: Read-only search over the knowledge base
    rules:
      - id: allow-kb-search
        action: kb.search
        effect: allow
        reason: Read-only KB access is pre-approved for all support agents
        conditions:
          max_input_bytes: 65536
          required_scopes: ["kb:read"]
      - id: deny-everything-else
        action: "*"
        effect: deny
        reason: Default deny. Only explicitly listed actions are permitted.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ._textio import TextDecodeError, read_text
from .canonical import digest_bytes
from .receipt import Decision

__all__ = [
    "Policy",
    "PolicyError",
    "PolicyRule",
    "Capability",
    "Evaluation",
    "load_policy",
]


class PolicyError(Exception):
    """Raised when a policy document cannot be understood. Fail closed."""


@dataclass(frozen=True)
class Capability:
    """A permission the subject has been granted up front."""

    name: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description}


@dataclass(frozen=True)
class PolicyRule:
    """One rule. ``action`` supports glob patterns."""

    id: str
    action: str
    effect: str  # "allow" | "deny" | "halt"
    reason: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)

    def matches(self, action: str) -> bool:
        if self.action == action:
            return True
        return fnmatch.fnmatchcase(action, self.action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "effect": self.effect,
            "reason": self.reason,
            "conditions": self.conditions,
        }


@dataclass(frozen=True)
class Evaluation:
    """The result of evaluating one action against the policy."""

    decision: Decision
    reason: str
    rule_id: str
    policy_id: str
    policy_digest: str
    conditions_checked: dict[str, Any] = field(default_factory=dict)

    @property
    def permitted(self) -> bool:
        return self.decision is Decision.ALLOW


@dataclass(frozen=True)
class Policy:
    """A parsed policy document."""

    version: int
    subject: str
    policy_id: str
    policy_digest: str
    capabilities: tuple[Capability, ...]
    rules: tuple[PolicyRule, ...]

    def capability_names(self) -> set[str]:
        return {c.name for c in self.capabilities}

    def find_rule(self, action: str) -> PolicyRule | None:
        """First matching rule wins. Rule order in the document is significant."""
        for rule in self.rules:
            if rule.matches(action):
                return rule
        return None

    def evaluate(
        self,
        action: str,
        *,
        inputs: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> Evaluation:
        """Evaluate ``action``. Never raises for a merely disallowed action.

        A malformed or contradictory precondition yields HALT rather than
        ALLOW: we could not establish that the action was safe.
        """
        inputs = inputs or {}
        context = context or {}

        rule = self.find_rule(action)
        if rule is None:
            return Evaluation(
                decision=Decision.DENY,
                reason=(
                    f"no policy rule matches action {action!r}; "
                    "this policy denies by default"
                ),
                rule_id="<none>",
                policy_id=self.policy_id,
                policy_digest=self.policy_digest,
            )

        if rule.effect == "deny":
            return Evaluation(
                decision=Decision.DENY,
                reason=rule.reason or f"rule {rule.id!r} denies {action!r}",
                rule_id=rule.id,
                policy_id=self.policy_id,
                policy_digest=self.policy_digest,
            )

        if rule.effect == "halt":
            return Evaluation(
                decision=Decision.HALT,
                reason=rule.reason or f"rule {rule.id!r} halts {action!r}",
                rule_id=rule.id,
                policy_id=self.policy_id,
                policy_digest=self.policy_digest,
            )

        if rule.effect != "allow":
            # Unknown effect is a policy authoring error. Fail closed.
            return Evaluation(
                decision=Decision.HALT,
                reason=(
                    f"rule {rule.id!r} has unknown effect {rule.effect!r}; "
                    "halting because the intent of the rule is unclear"
                ),
                rule_id=rule.id,
                policy_id=self.policy_id,
                policy_digest=self.policy_digest,
            )

        # --- preconditions -------------------------------------------------
        checked: dict[str, Any] = {}

        # 1. capability must have been declared. An empty (or omitted)
        # capability list is not a wildcard: the module contract is that an
        # action the subject was never granted is DENIED. Skipping the check
        # when the list is empty would be a default-allow path, which is
        # exactly what this gate exists to rule out.
        declared = self.capability_names()
        if not declared or action not in declared:
            return Evaluation(
                decision=Decision.DENY,
                reason=(
                    f"action {action!r} was never declared as a capability of "
                    f"{self.subject!r}"
                    + ("" if declared else " (the policy declares no capabilities)")
                ),
                rule_id=rule.id,
                policy_id=self.policy_id,
                policy_digest=self.policy_digest,
                conditions_checked={"capability_declared": False},
            )
        checked["capability_declared"] = True

        # 2. size precondition. A malformed limit is a policy authoring error:
        # the intent cannot be established, so HALT rather than raise (and
        # certainly rather than ALLOW).
        max_bytes = rule.conditions.get("max_input_bytes")
        if max_bytes is not None:
            actual = _payload_size(inputs)
            checked["input_bytes"] = actual
            checked["max_input_bytes"] = max_bytes
            try:
                limit = int(max_bytes)
            except (TypeError, ValueError):
                return Evaluation(
                    decision=Decision.HALT,
                    reason=(
                        f"rule {rule.id!r} has a non-integer max_input_bytes "
                        f"({max_bytes!r}); halting because the size "
                        "precondition cannot be evaluated"
                    ),
                    rule_id=rule.id,
                    policy_id=self.policy_id,
                    policy_digest=self.policy_digest,
                    conditions_checked=checked,
                )
            if actual > limit:
                return Evaluation(
                    decision=Decision.DENY,
                    reason=(
                        f"input payload is {actual} bytes, exceeding the "
                        f"{max_bytes} byte limit for {action!r}"
                    ),
                    rule_id=rule.id,
                    policy_id=self.policy_id,
                    policy_digest=self.policy_digest,
                    conditions_checked=checked,
                )
        # 3. required scopes
        required = rule.conditions.get("required_scopes")
        if required:
            granted = set(context.get("scopes") or [])
            missing = [s for s in required if s not in granted]
            checked["required_scopes"] = list(required)
            checked["granted_scopes"] = sorted(granted)
            if missing:
                return Evaluation(
                    decision=Decision.DENY,
                    reason=(
                        f"missing required scope(s) {missing} for action {action!r}"
                    ),
                    rule_id=rule.id,
                    policy_id=self.policy_id,
                    policy_digest=self.policy_digest,
                    conditions_checked=checked,
                )

        # 4. explicit precondition function, if the caller supplied one
        checker = rule.conditions.get("check")
        if callable(checker):
            try:
                outcome = checker(inputs=inputs, context=context)
            except Exception as exc:  # noqa: BLE001 - deliberate: fail closed
                return Evaluation(
                    decision=Decision.HALT,
                    reason=(
                        f"precondition check for rule {rule.id!r} raised "
                        f"{type(exc).__name__}: {exc}; halting because safety "
                        "could not be established"
                    ),
                    rule_id=rule.id,
                    policy_id=self.policy_id,
                    policy_digest=self.policy_digest,
                    conditions_checked=checked,
                )
            checked["custom_check"] = True
            if outcome is not True:
                return Evaluation(
                    decision=Decision.DENY,
                    reason=(
                        f"precondition check for rule {rule.id!r} did not pass"
                        + (f": {outcome}" if outcome is not False else "")
                    ),
                    rule_id=rule.id,
                    policy_id=self.policy_id,
                    policy_digest=self.policy_digest,
                    conditions_checked=checked,
                )

        return Evaluation(
            decision=Decision.ALLOW,
            reason=rule.reason or f"rule {rule.id!r} permits {action!r}",
            rule_id=rule.id,
            policy_id=self.policy_id,
            policy_digest=self.policy_digest,
            conditions_checked=checked,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "subject": self.subject,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "rules": [r.to_dict() for r in self.rules],
        }

    def with_check(self, rule_id: str, check: Any) -> "Policy":
        """Return a copy of this policy with a callable precondition attached.

        A precondition that cannot be loaded from YAML is injected here
        instead. The policy stays immutable.

        Note that a callable cannot be folded into ``policy_digest``, because
        it is not serializable. What the digest does cover is the rule
        definition itself; the check's behaviour is evidenced by the chain
        receipts, each of which records the rule id that produced it.
        """
        if not callable(check):
            raise PolicyError(f"check for rule {rule_id!r} must be callable")
        new_rules = []
        found = False
        for rule in self.rules:
            if rule.id == rule_id:
                found = True
                new_rules.append(
                    PolicyRule(
                        id=rule.id,
                        action=rule.action,
                        effect=rule.effect,
                        reason=rule.reason,
                        conditions={**rule.conditions, "check": check},
                    )
                )
            else:
                new_rules.append(rule)
        if not found:
            raise PolicyError(f"no rule with id {rule_id!r}")
        return Policy(
            version=self.version,
            subject=self.subject,
            policy_id=self.policy_id,
            policy_digest=self.policy_digest,
            capabilities=self.capabilities,
            rules=tuple(new_rules),
        )


def _payload_size(inputs: dict[str, Any]) -> int:
    """Size of the *actual* payload in bytes, not its digest.

    The limit in a policy is a limit on how much data the agent may push
    through, so it has to be measured on the payload itself. Measuring the
    digest would compare a fixed-length hash against a byte limit, which is
    meaningless.
    """
    if not inputs:
        return 0
    return len(json.dumps(inputs, ensure_ascii=False, default=str).encode("utf-8"))


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Load a policy from a YAML file path or an in-memory mapping.

    Any structural problem raises :class:`PolicyError`. The caller must treat
    that as a hard stop: a policy that cannot be parsed is not a policy that
    permits everything, it is a policy that permits nothing.
    """
    if isinstance(source, dict):
        raw = source
        origin = "<dict>"
    else:
        path = Path(source)
        if not path.exists():
            raise PolicyError(f"policy file not found: {path}")
        try:
            text = read_text(path, kind="policy")
        except TextDecodeError as exc:
            # Fail closed with a domain error: a policy that cannot be read is
            # a policy that permits nothing, and the caller gets a clear
            # message instead of a bare UnicodeDecodeError traceback.
            raise PolicyError(str(exc)) from exc
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy file {path} is not valid YAML: {exc}") from exc
        origin = str(path)

    if not isinstance(raw, dict):
        raise PolicyError(f"policy in {origin} must be a mapping, got {type(raw).__name__}")

    version = raw.get("version")
    if not isinstance(version, int):
        raise PolicyError(f"policy in {origin} is missing an integer 'version'")

    subject = raw.get("subject")
    if not isinstance(subject, str) or not subject:
        raise PolicyError(f"policy in {origin} is missing a non-empty 'subject'")

    rules_raw = raw.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise PolicyError(f"policy in {origin} must define a non-empty 'rules' list")

    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise PolicyError(f"rule #{index} in {origin} must be a mapping")
        rule_id = item.get("id")
        action = item.get("action")
        effect = item.get("effect")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule #{index} in {origin} is missing 'id'")
        if rule_id in seen_ids:
            raise PolicyError(f"duplicate rule id {rule_id!r} in {origin}")
        seen_ids.add(rule_id)
        if not isinstance(action, str) or not action:
            raise PolicyError(f"rule {rule_id!r} in {origin} is missing 'action'")
        if effect not in ("allow", "deny", "halt"):
            raise PolicyError(
                f"rule {rule_id!r} in {origin} has invalid effect {effect!r}; "
                "expected one of allow, deny, halt"
            )
        conditions = item.get("conditions") or {}
        if not isinstance(conditions, dict):
            raise PolicyError(f"rule {rule_id!r} in {origin} has non-mapping conditions")
        # A callable precondition cannot survive a YAML round-trip, so it must
        # be injected in Python rather than loaded from a file. Any 'check' key
        # in the document is therefore an authoring error — including a bare
        # string, which would silently never run.
        if "check" in conditions:
            raise PolicyError(
                f"rule {rule_id!r} in {origin} has a 'check' condition. "
                "Callable preconditions must be supplied in Python via "
                "Policy.with_check(), not in a YAML document."
            )
        rules.append(
            PolicyRule(
                id=rule_id,
                action=action,
                effect=effect,
                reason=str(item.get("reason", "")),
                conditions=conditions,
            )
        )

    caps_raw = raw.get("capabilities") or []
    if not isinstance(caps_raw, list):
        raise PolicyError(f"policy in {origin} has non-list 'capabilities'")
    capabilities: list[Capability] = []
    for index, item in enumerate(caps_raw):
        if isinstance(item, str):
            capabilities.append(Capability(name=item))
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            capabilities.append(
                Capability(
                    name=item["name"],
                    description=str(item.get("description", "")),
                )
            )
        else:
            raise PolicyError(f"capability #{index} in {origin} is malformed")

    policy_id = str(raw.get("policy_id") or digest_bytes(raw)[:16])
    policy_digest = digest_bytes(
        {
            "version": version,
            "subject": subject,
            "capabilities": [c.to_dict() for c in capabilities],
            "rules": [r.to_dict() for r in rules],
        }
    )

    return Policy(
        version=version,
        subject=subject,
        policy_id=policy_id,
        policy_digest=policy_digest,
        capabilities=tuple(capabilities),
        rules=tuple(rules),
    )

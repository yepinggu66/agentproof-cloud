"""The signed decision receipt.

A *receipt* is the unit of evidence agentproof produces. One receipt describes
one decision: an actor asked to do something, a policy layer decided, and the
decision was signed **before** the action was allowed to run.

Why pre-execution matters
-------------------------
An audit trail written by the agent after the fact is a claim, not evidence.
If the model itself decides what to log, a compromised or merely confused
model can shape the record. agentproof inverts this: the receipt is issued by
the gate, and it exists before the side effect happens. A receipt with no
matching action outcome is therefore a real finding ("approved but never
executed"), not an empty file.

The chain
---------
Each receipt carries ``prev_hash``. The record hash covers the receipt body
*including* the previous hash, so any edit to an earlier receipt invalidates
every later one. See :mod:`agentproof.core.chain`.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .canonical import CANONICAL_FORMAT_VERSION, digest_bytes

__all__ = [
    "Decision",
    "Receipt",
    "new_nonce",
    "utc_now",
]


class Decision(str, Enum):
    """The outcome of a policy evaluation.

    There is deliberately no ``ALLOW_BY_DEFAULT``. The only path to ``ALLOW``
    is an explicit policy rule that matched and every precondition held.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    #: Preconditions could not be evaluated (missing capability, unreachable
    #: dependency, ambiguous input). The action must not proceed.
    HALT = "HALT"

    @property
    def is_permitted(self) -> bool:
        return self is Decision.ALLOW


def utc_now() -> _dt.datetime:
    """Timezone-aware current time in UTC, truncated to microseconds.

    Truncating keeps the timestamp byte-identical after a JSON round-trip,
    which the canonicalizer relies on.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    return now.replace(microsecond=now.microsecond)


def new_nonce() -> str:
    """Return a fresh unique nonce for replay protection."""
    return uuid.uuid4().hex


@dataclass(frozen=True)
class Receipt:
    """One signed decision. Immutable once created."""

    seq: int
    nonce: str
    issued_at: str
    actor: str
    action: str
    decision: Decision
    reason: str
    policy_id: str
    policy_digest: str
    inputs_digest: str
    context: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    record_hash: str = ""
    signature: str = ""

    def body(self) -> dict[str, Any]:
        """The signed portion of the receipt.

        Excludes ``record_hash`` and ``signature``, which are derived from this
        body. Deliberately excludes nothing else: anything that affects the
        decision must be inside the signature.
        """
        return {
            "format": CANONICAL_FORMAT_VERSION,
            "seq": self.seq,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "actor": self.actor,
            "action": self.action,
            "decision": self.decision.value,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "inputs_digest": self.inputs_digest,
            "context": self.context,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        """Hash of :meth:`body` — the value chained to the next receipt."""
        return digest_bytes(self.body())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "record_hash": self.record_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Receipt":
        if not isinstance(data, dict):
            raise ValueError(
                f"receipt must be a mapping, got {type(data).__name__}"
            )
        missing = [
            k
            for k in (
                "seq",
                "nonce",
                "issued_at",
                "actor",
                "action",
                "decision",
                "reason",
                "policy_id",
                "policy_digest",
                "inputs_digest",
            )
            if k not in data
        ]
        if missing:
            raise ValueError(f"receipt is missing required fields: {missing}")
        return cls(
            seq=int(data["seq"]),
            nonce=str(data["nonce"]),
            issued_at=str(data["issued_at"]),
            actor=str(data["actor"]),
            action=str(data["action"]),
            decision=Decision(data["decision"]),
            reason=str(data.get("reason", "")),
            policy_id=str(data["policy_id"]),
            policy_digest=str(data["policy_digest"]),
            inputs_digest=str(data["inputs_digest"]),
            context=dict(data.get("context") or {}),
            prev_hash=str(data.get("prev_hash", "")),
            record_hash=str(data.get("record_hash", "")),
            signature=str(data.get("signature", "")),
        )

    def with_signature(self, signature: str, record_hash: str) -> "Receipt":
        from dataclasses import replace

        return replace(self, signature=signature, record_hash=record_hash)

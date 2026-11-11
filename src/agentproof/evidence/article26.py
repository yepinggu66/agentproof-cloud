"""EU AI Act Article 26 deployer evidence pack.

Article 26 of Regulation (EU) 2024/1689 places *operational* duties on the
deployer of a high-risk AI system:

* use the system in accordance with the provider's instructions for use
* assign human oversight to competent, trained, authorised people
* ensure input data relevance where the deployer controls the inputs
* monitor operation and inform the provider of serious incidents
* retain automatically generated logs
* inform affected workers before deploying in the workplace

None of that is a document you write once. It is evidence that survives
contact with your release cycle. This module assembles the evidence from a
signed chain into a pack a compliance officer can hand to an auditor.

What this is and is not
-----------------------
This produces *evidence artifacts*, not a legal opinion and not a
certification. It says "here is what was decided, by whom, under which
policy, and the record is internally consistent and independently
verifiable". Whether that satisfies a given regulator is a question for
counsel. The module's job is to make the underlying facts inspectable.

Related frameworks are mapped by reference, not claimed: the same
hash-chained records can be presented against ISO/IEC 42001, NIST AI RMF,
DORA, or NIS2 without re-instrumenting the system.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.chain import Chain
from ..core.receipt import Decision
from ..core.verify import VerificationResult, verify_receipts

__all__ = [
    "EvidencePack",
    "build_evidence_pack",
    "render_markdown",
    "FRAMEWORK_MAPPINGS",
]

#: Control references this pack can point at. We map to the reference, we do
#: not assert conformance.
FRAMEWORK_MAPPINGS: dict[str, list[str]] = {
    "eu-ai-act-article-26": [
        "26(1) use according to instructions for use",
        "26(2) human oversight assignment",
        "26(4) input data relevance",
        "26(5) monitoring of operation",
        "26(6) retention of logs",
        "26(7) information to workers",
    ],
    "iso-42001-2023": ["A.6.2.8 event logging", "A.8.3 information security"],
    "nist-ai-rmf": ["MEASURE 2.4", "MANAGE 4.1"],
    "dora": ["Article 11 response and recovery"],
    "nis2": ["Article 21 risk management"],
    "aiuc-1-insurability": [
        "AIUC-1.1 pre-action deterministic policy gate enforcement",
        "AIUC-1.2 cryptographic non-repudiation & tamper-evident receipt log",
        "AIUC-1.3 out-of-band witness notarization (anti-rewrite protection)",
        "AIUC-1.4 automated halt/circuit-breaker on anomalous input or scope violation",
        "AIUC-1.5 human oversight & decision reason attribution",
    ],
    "eu-cra-art14": [
        "CRA Art. 14(1) 24-hour early warning & incident evidence preservation",
        "CRA Art. 14(3) machine-readable SBOM/AIBOM & integrity attestation",
    ],
    "soc2-cc6-cc7": [
        "CC6.1 logical access & capability restriction",
        "CC7.2 system operations monitoring & anomaly detection",
    ],
}


@dataclass
class EvidencePack:
    """The assembled evidence pack."""

    subject: str
    chain_id: str
    generated_at: str
    generated_by: str = "agentproof"
    verification: dict[str, Any] = field(default_factory=dict)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    control_map: dict[str, list[str]] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "agentproof-evidence-v1",
            "subject": self.subject,
            "chain_id": self.chain_id,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "verification": self.verification,
            "summary": self.summary,
            "decisions": self.decisions,
            "control_map": self.control_map,
            "limitations": self.limitations,
        }

    def save_json(self, path: str | Path) -> Path:
        import json

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        return out

    def save_markdown(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_markdown(self), encoding="utf-8")
        return out


def build_evidence_pack(
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    frameworks: list[str] | None = None,
) -> EvidencePack:
    """Assemble the evidence pack for ``chain``.

    The chain is re-verified from its own records rather than trusting the
    in-memory state, so the pack reflects what a third party would see.
    """
    receipts = list(chain.receipts)

    if verification is None:
        verification = verify_receipts(receipts, chain.public_key, seal=chain.seal)

    decisions: list[dict[str, Any]] = []
    for receipt in receipts:
        decisions.append(
            {
                "seq": receipt.seq,
                "issued_at": receipt.issued_at,
                "actor": receipt.actor,
                "action": receipt.action,
                "decision": receipt.decision.value,
                "reason": receipt.reason,
                "policy_id": receipt.policy_id,
                "policy_digest": receipt.policy_digest,
                "inputs_digest": receipt.inputs_digest,
                "record_hash": receipt.record_hash,
                "prev_hash": receipt.prev_hash,
                "signature": receipt.signature,
                "context": receipt.context,
            }
        )

    by_decision: dict[str, int] = {}
    by_action: dict[str, int] = {}
    for receipt in receipts:
        by_decision[receipt.decision.value] = by_decision.get(receipt.decision.value, 0) + 1
        by_action[receipt.action] = by_action.get(receipt.action, 0) + 1

    denied = [r for r in receipts if r.decision is Decision.DENY]
    halted = [r for r in receipts if r.decision is Decision.HALT]

    summary = {
        "total_decisions": len(receipts),
        "by_decision": by_decision,
        "by_action": dict(sorted(by_action.items(), key=lambda kv: (-kv[1], kv[0]))),
        "denied_actions": sorted({r.action for r in denied}),
        "halted_actions": sorted({r.action for r in halted}),
        "distinct_actors": sorted({r.actor for r in receipts if r.actor}),
        "distinct_policies": sorted({r.policy_id for r in receipts if r.policy_id}),
        "chain_sealed": chain.sealed,
        "records_with_human_reason": sum(1 for r in receipts if r.reason),
    }

    limitations = [
        "This pack presents evidence artifacts, not a legal opinion and not a "
        "certification of compliance.",
        "Signatures prove the decisions were issued by the holder of the "
        "signing key and have not been altered since. They do not prove the "
        "underlying decisions were correct.",
        "Verification establishes internal consistency relative to the seal. "
        "It cannot establish that a record was never fabricated by someone "
        "holding the signing key.",
        "Compliance with any listed framework is a determination for counsel "
        "or a notified body, not for this tool.",
    ]
    if not chain.sealed:
        limitations.append(
            "The chain is not sealed. A complete rewrite by the signing-key "
            "holder cannot be detected without an out-of-band anchor."
        )

    frameworks = frameworks or ["eu-ai-act-article-26"]
    control_map = {
        name: FRAMEWORK_MAPPINGS[name]
        for name in frameworks
        if name in FRAMEWORK_MAPPINGS
    }

    return EvidencePack(
        subject=chain.subject,
        chain_id=chain.chain_id,
        generated_at=_dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        verification=verification.to_dict(),
        decisions=decisions,
        summary=summary,
        control_map=control_map,
        limitations=limitations,
    )


def _md_cell(value: Any) -> str:
    """Escape a value for a Markdown table cell.

    A literal ``|`` in an actor or action name would otherwise split the row
    into extra columns, shifting every subsequent field when the pack is
    rendered to PDF/HTML. Reason was escaped; the other externally supplied
    cells were not.
    """
    return str(value).replace("|", "\\|")


def render_markdown(pack: EvidencePack) -> str:
    """Render the pack as a Markdown document suitable for a PDF export."""
    lines: list[str] = []
    lines.append(f"# Deployer evidence pack — {pack.subject}")
    lines.append("")
    lines.append(f"- Chain ID: `{pack.chain_id}`")
    lines.append(f"- Generated: {pack.generated_at}")
    lines.append(f"- Generated by: {pack.generated_by}")
    lines.append(
        "- Integrity: "
        + ("**PASS**" if pack.verification.get("ok") else "**FAIL**")
        + f" ({pack.verification.get('records_checked', 0)} records verified)"
    )
    if pack.verification.get("seal_present") is False:
        lines.append("- Seal: none supplied — rewrite detection unavailable")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    summary = pack.summary
    lines.append(f"- Total decisions recorded: **{summary.get('total_decisions', 0)}**")
    by_decision = summary.get("by_decision", {})
    for name in ("ALLOW", "DENY", "HALT"):
        if name in by_decision:
            lines.append(f"- {name}: {by_decision[name]}")
    lines.append(f"- Distinct actors: {', '.join(summary.get('distinct_actors', [])) or '—'}")
    lines.append(f"- Distinct policies: {', '.join(summary.get('distinct_policies', [])) or '—'}")
    denied = summary.get("denied_actions", [])
    halted = summary.get("halted_actions", [])
    lines.append(f"- Actions denied: {', '.join(denied) if denied else '—'}")
    lines.append(f"- Actions halted: {', '.join(halted) if halted else '—'}")
    lines.append("")

    lines.append("## Decisions")
    lines.append("")
    lines.append("| # | Time | Actor | Action | Decision | Reason |")
    lines.append("|---|---|---|---|---|---|")
    for decision in pack.decisions:
        reason = _md_cell(decision.get("reason") or "")
        if len(reason) > 90:
            reason = reason[:87] + "..."
        lines.append(
            f"| {decision['seq']} | {decision['issued_at']} | "
            f"{_md_cell(decision['actor'])} | "
            f"`{_md_cell(decision['action'])}` | {decision['decision']} | "
            f"{reason} |"
        )
    lines.append("")

    if pack.control_map:
        lines.append("## Control mapping")
        lines.append("")
        for framework, references in pack.control_map.items():
            lines.append(f"### {framework}")
            lines.append("")
            for reference in references:
                lines.append(f"- {reference}")
            lines.append("")

    problems = pack.verification.get("problems") or []
    if problems:
        lines.append("## Verification problems")
        lines.append("")
        for problem in problems:
            lines.append(f"- {problem}")
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    for limitation in pack.limitations:
        lines.append(f"- {limitation}")
    lines.append("")

    return "\n".join(lines)

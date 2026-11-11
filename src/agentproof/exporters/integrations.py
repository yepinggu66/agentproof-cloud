"""Connectors for Vanta, Drata, and Datadog — the Strategic M&A Distribution Wedge.

Why these connectors matter commercially:
When enterprise customers push AgentProof cryptographic evidence directly into
Vanta (SOC 2 / ISO 42001), Drata, or Datadog Cloud SIEM, two things happen:
1. Immediate B2B Willingness-to-Pay: Compliance officers buy AgentProof Pro/Enterprise
   because it auto-checks their AI governance controls in Vanta/Drata.
2. Strategic Acquirer Visibility: Product & CorpDev teams at Vanta, Drata, and
   Datadog see AgentProof as the de-facto AI agent evidence feeder across their
   mutual enterprise accounts.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from ..core.chain import Chain
from ..core.verify import VerificationResult, verify_receipts
from ..evidence.article26 import build_evidence_pack
from ..evidence.insurability import compute_insurability_score

SUPPORTED_TARGETS = ("vanta", "drata", "datadog")


def build_vanta_payload(
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    notarized_count: int = 0,
) -> dict[str, Any]:
    """Format a chain into a Vanta Custom Evidence & Continuous Monitoring resource."""
    if verification is None:
        verification = verify_receipts(list(chain.receipts), chain.public_key, seal=chain.seal)
    pack = build_evidence_pack(
        chain,
        verification=verification,
        frameworks=["eu-ai-act-article-26", "iso-42001-2023", "soc2-cc6-cc7", "aiuc-1-insurability"],
    )
    scorecard = compute_insurability_score(
        chain, verification=verification, notarized_count=notarized_count
    )

    return {
        "schema_version": "vanta.custom_evidence.v1",
        "integration_source": "agentproof",
        "resource_type": "ai_agent_cryptographic_control_chain",
        "external_id": f"agentproof:{chain.chain_id}",
        "display_name": f"AgentProof Pre-Action Ledger — {chain.subject or chain.chain_id}",
        "generated_at": pack.generated_at,
        "status": "PASS" if verification.ok else "FAIL",
        "controls_satisfied": [
            "ISO42001-A.6.2.8",
            "ISO42001-A.8.3",
            "SOC2-CC6.1",
            "SOC2-CC7.2",
            "EU-AI-ACT-ART26",
            "AIUC-1",
        ],
        "insurability_scorecard": scorecard.to_dict(),
        "evidence_summary": pack.summary,
        "cryptographic_proof": {
            "chain_id": chain.chain_id,
            "public_key_ed25519": chain.public_key_hex,
            "records_verified": verification.records_checked,
            "final_hash": verification.final_hash,
            "sealed": chain.sealed,
            "problems": verification.problems,
        },
    }


def build_drata_payload(
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    notarized_count: int = 0,
) -> dict[str, Any]:
    """Format a chain into a Drata Autopilot Custom Connection payload."""
    if verification is None:
        verification = verify_receipts(list(chain.receipts), chain.public_key, seal=chain.seal)
    scorecard = compute_insurability_score(
        chain, verification=verification, notarized_count=notarized_count
    )

    return {
        "schema": "drata.autopilot.evidence.v1",
        "provider": "agentproof-cloud",
        "check_name": "AI Agent Pre-Execution Policy Gate & Cryptographic Audit Trail",
        "subject": chain.subject or chain.chain_id,
        "chain_id": chain.chain_id,
        "compliant": bool(verification.ok and len(chain.receipts) > 0),
        "underwriting_tier": scorecard.underwriting_tier,
        "insurability_score": scorecard.insurability_score,
        "metrics": scorecard.metrics,
        "attestation": {
            "public_key": chain.public_key_hex,
            "final_hash": verification.final_hash,
            "records_checked": verification.records_checked,
        },
    }


def build_datadog_payload(
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    notarized_count: int = 0,
) -> dict[str, Any]:
    """Format a chain into Datadog Cloud SIEM / Audit Trail intake events."""
    if verification is None:
        verification = verify_receipts(list(chain.receipts), chain.public_key, seal=chain.seal)
    scorecard = compute_insurability_score(
        chain, verification=verification, notarized_count=notarized_count
    )

    events: list[dict[str, Any]] = []
    for r in chain.receipts:
        status = "info" if r.decision.value == "ALLOW" else "warn" if r.decision.value == "DENY" else "error"
        events.append(
            {
                "ddsource": "agentproof",
                "service": chain.subject or "ai-agent",
                "status": status,
                "timestamp": r.issued_at,
                "message": f"[AgentProof {r.decision.value}] actor={r.actor} action={r.action}: {r.reason}",
                "ddtags": ",".join(
                    [
                        f"chain_id:{chain.chain_id}",
                        f"decision:{r.decision.value}",
                        f"policy_id:{r.policy_id}",
                        f"tier:{scorecard.underwriting_tier}",
                    ]
                ),
                "agentproof": {
                    "seq": r.seq,
                    "actor": r.actor,
                    "action": r.action,
                    "decision": r.decision.value,
                    "record_hash": r.record_hash,
                    "signature": r.signature,
                },
            }
        )

    return {
        "schema": "datadog.logs.intake.v2",
        "chain_id": chain.chain_id,
        "integrity_verified": verification.ok,
        "insurability_score": scorecard.insurability_score,
        "events": events,
    }


def build_target_export(
    target: str,
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    notarized_count: int = 0,
) -> dict[str, Any]:
    norm = target.strip().lower()
    if norm == "vanta":
        return build_vanta_payload(
            chain, verification=verification, notarized_count=notarized_count
        )
    if norm == "drata":
        return build_drata_payload(
            chain, verification=verification, notarized_count=notarized_count
        )
    if norm == "datadog":
        return build_datadog_payload(
            chain, verification=verification, notarized_count=notarized_count
        )
    raise ValueError(
        f"Unsupported export target {target!r}; choose from {SUPPORTED_TARGETS}"
    )


def push_export_payload(
    payload: dict[str, Any],
    *,
    push_url: str,
    api_token: str = "",
) -> dict[str, Any]:
    """Push the formatted compliance payload to an external GRC/SIEM webhook endpoint."""
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
        headers["DD-API-KEY"] = api_token

    req = urllib.request.Request(
        push_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
        return {
            "status_code": resp.status,
            "response": json.loads(raw) if raw.strip().startswith("{") else raw,
        }

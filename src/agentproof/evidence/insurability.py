"""Lloyd's AIUC-1 Insurability Scorecard & Underwriting Risk Assessment.

Translates cryptographic receipt chains, policy enforcement metrics, and
out-of-band cloud witness notarization into an objective underwriting scorecard
(0–100) for AI liability insurers, CISOs, and compliance officers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.chain import Chain
from ..core.receipt import Decision
from ..core.verify import VerificationResult, verify_receipts


@dataclass
class InsurabilityScorecard:
    """Quantitative underwriting assessment for an AI agent deployment."""

    chain_id: str
    subject: str
    insurability_score: int  # 0 to 100
    underwriting_tier: str  # TIER_1_PREFERRED | TIER_2_STANDARD | TIER_3_SUBSTANDARD | UNINSURABLE
    premium_adjustment: str  # e.g. "-20% Preferred Discount"
    metrics: dict[str, Any] = field(default_factory=dict)
    strengths: list[str] = field(default_factory=list)
    remediations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "subject": self.subject,
            "insurability_score": self.insurability_score,
            "underwriting_tier": self.underwriting_tier,
            "premium_adjustment": self.premium_adjustment,
            "metrics": self.metrics,
            "strengths": self.strengths,
            "remediations": self.remediations,
        }


def compute_insurability_score(
    chain: Chain,
    *,
    verification: VerificationResult | None = None,
    notarized_count: int = 0,
) -> InsurabilityScorecard:
    """Compute the AIUC-1 insurability score (0–100) for ``chain``."""
    receipts = list(chain.receipts)
    if verification is None:
        verification = verify_receipts(receipts, chain.public_key, seal=chain.seal)

    total = len(receipts)
    if not verification.ok or total == 0:
        return InsurabilityScorecard(
            chain_id=chain.chain_id,
            subject=chain.subject,
            insurability_score=0,
            underwriting_tier="UNINSURABLE",
            premium_adjustment="Declined — Cryptographic verification failed or empty chain",
            metrics={
                "total_receipts": total,
                "integrity_ok": verification.ok,
                "notarized_count": notarized_count,
            },
            strengths=[],
            remediations=[
                "Restore cryptographic chain integrity and ensure all agent actions emit pre-execution receipts."
            ],
        )

    score = 0
    strengths: list[str] = []
    remediations: list[str] = []

    # 1. Cryptographic Integrity & Non-Repudiation (35 pts)
    score += 35
    strengths.append("100% pre-execution Ed25519 signature & hash-chain integrity verified.")

    # 2. Policy Gate Enforcement & Reason Attribution (25 pts)
    with_policy = sum(1 for r in receipts if r.policy_id and r.policy_digest)
    with_reason = sum(1 for r in receipts if r.reason)
    policy_ratio = with_policy / total
    reason_ratio = with_reason / total

    policy_pts = round(15 * policy_ratio + 10 * reason_ratio)
    score += policy_pts
    if policy_ratio == 1.0 and reason_ratio == 1.0:
        strengths.append("100% of decisions bound to immutable policy digests with explicit audit reasons.")
    else:
        remediations.append("Bind every receipt to a non-empty policy_id, policy_digest, and human-readable reason.")

    # 3. Active Guardrail Proof (DENY / HALT circuit breaker evidence) (15 pts)
    blocked = sum(1 for r in receipts if r.decision in (Decision.DENY, Decision.HALT))
    if blocked > 0:
        score += 15
        strengths.append(f"Fail-closed gate actively intercepted {blocked} unauthorized/halted action(s).")
    else:
        score += 10
        remediations.append(
            "Include negative regression tests (DENY/HALT) in evidence chain to prove circuit-breaker efficacy."
        )

    # 4. Out-of-Band Seal & Cloud Witness Notarization (25 pts) — The Cloud SaaS Upsell!
    notarized_ratio = min(1.0, notarized_count / total) if total > 0 else 0.0
    if notarized_ratio >= 1.0:
        score += 25
        strengths.append("100% of receipts counter-signed by AgentProof Cloud Out-of-Band Witness (anti-rewrite guaranteed).")
    elif chain.sealed:
        score += 15
        strengths.append("Chain is locally sealed with an anchor hash.")
        remediations.append(
            "Upgrade to AgentProof Cloud Pro/Enterprise for real-time third-party Witness counter-signing (+10 pts)."
        )
    else:
        remediations.append(
            "Chain is unsealed and lacks external Witness notarization. Seal the chain (`agentproof chain-seal`) "
            "or stream to AgentProof Cloud to prevent key-holder history rewrites (+25 pts)."
        )

    score = min(100, max(0, score))

    if score >= 90:
        tier = "TIER_1_PREFERRED"
        adj = "-20% Preferred Underwriting Discount Eligible"
    elif score >= 75:
        tier = "TIER_2_STANDARD"
        adj = "Standard Base Rate Eligible"
    elif score >= 55:
        tier = "TIER_3_SUBSTANDARD"
        adj = "+25% High-Deductible Surcharge (Missing External Witness)"
    else:
        tier = "UNINSURABLE"
        adj = "Underwriting Hold — Insufficient Controls"

    return InsurabilityScorecard(
        chain_id=chain.chain_id,
        subject=chain.subject,
        insurability_score=score,
        underwriting_tier=tier,
        premium_adjustment=adj,
        metrics={
            "total_receipts": total,
            "integrity_ok": verification.ok,
            "chain_sealed": chain.sealed,
            "notarized_count": notarized_count,
            "notarized_ratio": round(notarized_ratio, 4),
            "blocked_actions": blocked,
            "policy_coverage_ratio": round(policy_ratio, 4),
        },
        strengths=strengths,
        remediations=remediations,
    )

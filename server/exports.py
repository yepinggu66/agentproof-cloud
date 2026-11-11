"""Ecosystem export payloads: Vanta, Drata, Datadog, Lloyd's AIUC-1.

These are *mapping drafts* built from the tenant's signed ledger. Every pack
carries an explicit ``mapping_status`` and disclaimer: the field names follow
public documentation as closely as we can, but a vendor-certified integration
requires their SDK/schema review. Never present these as certified formats.

Fix a payload's content only by changing this module — it must stay
deterministic apart from ``generated_at`` and the ledger tail it reads.
"""

from __future__ import annotations

from typing import Any

__all__ = ["VENDORS", "build_export"]

VENDORS = {
    "vanta": {
        "name": "Vanta",
        "framework": "SOC 2 Type II",
        "accent": "#5B3DF5",
        "description": "把签名决策映射到 SOC 2 控制项，作为审计证据附件。",
    },
    "drata": {
        "name": "Drata",
        "framework": "ISO 27001 / SOC 2",
        "accent": "#00B3A4",
        "description": "按测试项输出连续监控结果，接入 Drata 证据库。",
    },
    "datadog": {
        "name": "Datadog",
        "framework": "Runtime monitoring",
        "accent": "#632CA6",
        "description": "把 DENY/HALT 决策推送为 Datadog 事件，进入现有告警通道。",
    },
    "aiuc1": {
        "name": "Lloyd's AIUC-1",
        "framework": "AIUC-1 核保问卷",
        "accent": "#C8A15A",
        "description": "生成承保方要求的 agent 行为证据与整改声明。",
    },
}

_DISCLAIMER = (
    "字段映射草案（mapping draft），按厂商公开文档整理，未经厂商认证；"
    "接入前请以对方最新 schema 为准。本文件是证据材料，不是合规认证。"
)


def build_export(
    vendor: str,
    *,
    tenant: dict[str, Any],
    plan: dict[str, Any],
    usage: dict[str, Any],
    events: list[dict[str, Any]],
    verification: dict[str, Any],
) -> dict[str, Any]:
    vendor_id = vendor.lower()
    if vendor_id not in VENDORS:
        raise ValueError(f"unknown vendor {vendor!r}")
    exporter = {
        "vanta": _vanta,
        "drata": _drata,
        "datadog": _datadog,
        "aiuc1": _aiuc1,
    }[vendor_id]
    return exporter(
        tenant=tenant,
        plan=plan,
        usage=usage,
        events=events,
        verification=verification,
    )


def _summary(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"ALLOW": 0, "HALT": 0, "DENY": 0}
    for event in events:
        if event["decision"] in counts:
            counts[event["decision"]] += 1
    return counts


def _integrity(verification: dict[str, Any]) -> dict[str, Any]:
    return {
        "result": verification["result"],
        "records": verification["records"],
        "final_hash": verification["final_hash"],
        "seal_hash": verification["seal"]["seal_hash"],
        "fingerprints": verification["fingerprints"],
    }


def _org(tenant: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tenant["company"],
        "tenant_id": tenant["id"],
        "email": tenant["email"],
        "plan": tenant["plan"],
    }


def _vanta(**kw: Any) -> dict[str, Any]:
    tenant, plan, usage = kw["tenant"], kw["plan"], kw["usage"]
    events, verification = kw["events"], kw["verification"]
    counts = _summary(events)
    controls = [
        {
            "control": "CC7.2",
            "name": "System monitoring — agent actions",
            "status": "PASS" if verification["result"] == "PASS" else "FAIL",
            "evidence": {
                "type": "signed_decision_ledger",
                "records": verification["records"],
                "decision_counts": counts,
                "hash_chain_final": verification["final_hash"],
                "sealed": verification["seal"]["present"],
            },
        },
        {
            "control": "CC7.3",
            "name": "Incident detection — denied actions",
            "status": "PASS",
            "evidence": {
                "type": "policy_denials",
                "denied": counts["DENY"],
                "halted": counts["HALT"],
                "sample": [
                    {"action": e["action"], "decision": e["decision"], "reason": e["reason"]}
                    for e in events
                    if e["decision"] in {"DENY", "HALT"}
                ][:10],
            },
        },
        {
            "control": "CC6.1",
            "name": "Logical access — policy gate",
            "status": "PASS" if plan["id"] != "free" else "PARTIAL",
            "evidence": {
                "type": "policy_enforcement",
                "mode": "deny-by-default",
                "signed_before_action": True,
            },
        },
    ]
    return {
        "format": "vanta.evidence_pack",
        "format_version": "draft-2026-11",
        "mapping_status": "draft",
        "generated_at": verification["verified_at"],
        "organization": _org(tenant),
        "framework": VENDORS["vanta"]["framework"],
        "period": {"start": usage["period_start"], "end": verification["verified_at"]},
        "controls": controls,
        "integrity": _integrity(verification),
        "disclaimer": _DISCLAIMER,
    }


def _drata(**kw: Any) -> dict[str, Any]:
    tenant, usage = kw["tenant"], kw["usage"]
    events, verification = kw["events"], kw["verification"]
    counts = _summary(events)
    return {
        "format": "drata.monitoring_results",
        "format_version": "draft-2026-11",
        "mapping_status": "draft",
        "generated_at": verification["verified_at"],
        "organization": _org(tenant),
        "checks": [
            {
                "checkId": "AGENT-LEDGER-01",
                "name": "Agent decisions are signed before execution",
                "status": "PASS" if verification["result"] == "PASS" else "FAIL",
                "evidence": {
                    "records": verification["records"],
                    "final_hash": verification["final_hash"],
                    "seal_hash": verification["seal"]["seal_hash"],
                    "platform_fingerprint": verification["fingerprints"]["platform"],
                    "tenant_fingerprint": verification["fingerprints"]["tenant"],
                },
            },
            {
                "checkId": "AGENT-POLICY-02",
                "name": "Deny-by-default policy gate is enforced",
                "status": "PASS",
                "evidence": {"denied": counts["DENY"], "halted": counts["HALT"], "allowed": counts["ALLOW"]},
            },
            {
                "checkId": "AGENT-RETENTION-03",
                "name": "Ledger retention meets plan policy",
                "status": "PASS",
                "evidence": {"retention_days": usage["retention_days"], "plan": tenant["plan"]},
            },
        ],
        "integrity": _integrity(verification),
        "disclaimer": _DISCLAIMER,
    }


def _datadog(**kw: Any) -> dict[str, Any]:
    tenant = kw["tenant"]
    events, verification = kw["events"], kw["verification"]
    counts = _summary(events)
    payload = {
        "title": f"AgentProof: ledger {verification['result']} ({verification['records']} records)",
        "text": (
            f"tenant={tenant['id']} company={tenant['company']}\n"
            f"ALLOW={counts['ALLOW']} HALT={counts['HALT']} DENY={counts['DENY']}\n"
            f"final_hash={verification['final_hash']}\n"
            f"seal_hash={verification['seal']['seal_hash']}"
        ),
        "priority": "normal" if verification["result"] == "PASS" else "high",
        "alert_type": "info" if verification["result"] == "PASS" else "error",
        "tags": [
            "service:agentproof",
            f"tenant:{tenant['id']}",
            f"plan:{tenant['plan']}",
            f"integrity:{verification['result'].lower()}",
        ],
        "source_type_name": "agentproof",
    }
    denied = [
        {
            "title": f"Agent action {e['decision']}: {e['action']}",
            "text": e["reason"],
            "priority": "normal",
            "alert_type": "warning" if e["decision"] == "DENY" else "error",
            "tags": ["service:agentproof", "decision:deny", f"tenant:{tenant['id']}"],
        }
        for e in events
        if e["decision"] in {"DENY", "HALT"}
    ][:20]
    return {
        "format": "datadog.events.v1",
        "format_version": "draft-2026-11",
        "mapping_status": "draft",
        "generated_at": verification["verified_at"],
        "organization": _org(tenant),
        "endpoint": "POST https://api.datadoghq.com/api/v1/events",
        "events": [payload, *denied],
        "integrity": _integrity(verification),
        "disclaimer": _DISCLAIMER,
    }


def _aiuc1(**kw: Any) -> dict[str, Any]:
    tenant, usage, plan = kw["tenant"], kw["usage"], kw["plan"]
    events, verification = kw["events"], kw["verification"]
    counts = _summary(events)
    return {
        "format": "lloyds.aiuc1.underwriting_pack",
        "format_version": "draft-2026-11",
        "mapping_status": "draft",
        "generated_at": verification["verified_at"],
        "insured": _org(tenant),
        "policy": {"id": "AIUC-1", "edition": "2026", "line": "AI agent liability"},
        "attestations": [
            {
                "control": "AIUC-1.3",
                "requirement": "Agent actions are attributable and non-repudiable",
                "status": "attested" if verification["result"] == "PASS" else "exception",
                "evidence": {
                    "mechanism": "dual Ed25519 signature per record",
                    "records": verification["records"],
                    "final_hash": verification["final_hash"],
                },
            },
            {
                "control": "AIUC-1.4",
                "requirement": "Pre-action authorization with deny-by-default policy",
                "status": "attested",
                "evidence": {"allowed": counts["ALLOW"], "denied": counts["DENY"], "halted": counts["HALT"]},
            },
            {
                "control": "AIUC-1.7",
                "requirement": "Tamper-evident retention for the underwriting period",
                "status": "attested",
                "evidence": {"retention_days": usage["retention_days"], "seal": verification["seal"]},
            },
        ],
        "risk_summary": {
            "sample_size": verification["records"],
            "denied_actions": counts["DENY"],
            "halted_actions": counts["HALT"],
            "integrity": verification["result"],
            "plan": plan["id"],
        },
        "integrity": _integrity(verification),
        "disclaimer": _DISCLAIMER,
    }

"""Scan report aggregation, risk scoring, and automatic starter policy synthesis."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .mcp_scanner import scan_mcp_configs
from .python_scanner import scan_python_files


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_PENALTY = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    category: str
    location: str
    title: str
    detail: str
    remediation: str
    action_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "location": self.location,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "action_name": self.action_name,
        }


@dataclass
class ScanReport:
    target: str
    scanned_at: str
    risk_score: int  # 0 (safe) to 100 (critical exposure)
    security_grade: str  # A, B, C, D, F
    findings: list[Finding] = field(default_factory=list)
    discovered_tools: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "agentproof-scan-v1",
            "target": self.target,
            "scanned_at": self.scanned_at,
            "risk_score": self.risk_score,
            "security_grade": self.security_grade,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "discovered_tools": self.discovered_tools,
        }

    def render(self) -> str:
        lines: list[str] = []
        lines.append(f"AgentProof Shadow AI & Tool Surface Scan — {self.target}")
        lines.append("=" * 64)
        lines.append(
            f" Exposure Risk Score : {self.risk_score}/100  (Grade: {self.security_grade})"
        )
        lines.append(
            f" Tools Discovered    : {len(self.discovered_tools)} "
            f"(MCP servers: {self.summary.get('mcp_servers', 0)}, "
            f"Python tools: {self.summary.get('python_tools', 0)})"
        )
        by_sev = self.summary.get("by_severity", {})
        lines.append(
            f" Findings            : {len(self.findings)} total "
            f"(CRITICAL: {by_sev.get('CRITICAL', 0)}, "
            f"HIGH: {by_sev.get('HIGH', 0)}, "
            f"MEDIUM: {by_sev.get('MEDIUM', 0)})"
        )
        lines.append("")

        if not self.findings:
            lines.append("PASS — No unguarded high-risk tools or Shadow MCP issues found.")
            return "\n".join(lines)

        for idx, f in enumerate(self.findings, 1):
            lines.append(f"[{idx}] [{f.severity.value}] {f.rule_id}: {f.title}")
            lines.append(f"    Location    : {f.location}")
            lines.append(f"    Detail      : {f.detail}")
            lines.append(f"    Remediation : {f.remediation}")
            lines.append("")

        lines.append(
            "Tip: Run `agentproof scan <dir> --init-policy policy.yaml` to "
            "auto-generate a fail-closed policy for all discovered tools."
        )
        return "\n".join(lines)


def run_workspace_scan(target: str | Path) -> ScanReport:
    """Scan ``target`` for MCP configs and Python agent tools."""
    root = Path(target)
    mcp_raw, mcp_tools = scan_mcp_configs(root)
    py_raw, py_tools = scan_python_files(root)

    all_raw = mcp_raw + py_raw
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_raw.sort(key=lambda item: (order.get(item["severity"], 9), item["rule_id"], item["location"]))

    findings = [
        Finding(
            rule_id=item["rule_id"],
            severity=Severity(item["severity"]),
            category=item["category"],
            location=item["location"],
            title=item["title"],
            detail=item["detail"],
            remediation=item["remediation"],
            action_name=item.get("action_name", ""),
        )
        for item in all_raw
    ]

    discovered = mcp_tools + py_tools
    penalty = sum(SEVERITY_PENALTY.get(f.severity, 5) for f in findings)
    risk_score = min(100, penalty)

    if risk_score == 0:
        grade = "A"
    elif risk_score <= 15:
        grade = "B"
    elif risk_score <= 35:
        grade = "C"
    elif risk_score <= 60:
        grade = "D"
    else:
        grade = "F"

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    return ScanReport(
        target=str(root),
        scanned_at=_dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        risk_score=risk_score,
        security_grade=grade,
        findings=findings,
        discovered_tools=discovered,
        summary={
            "total_findings": len(findings),
            "by_severity": by_sev,
            "mcp_servers": len(mcp_tools),
            "python_tools": len(py_tools),
            "unguarded_count": sum(1 for t in discovered if not t.get("guarded")),
        },
    )


def generate_starter_policy(
    report: ScanReport,
    *,
    subject: str = "discovered-agent-system",
) -> dict[str, Any]:
    """Synthesize a valid fail-closed ``policy.yaml`` structure from scan results."""
    capabilities: list[dict[str, str]] = []
    rules: list[dict[str, Any]] = []
    seen_actions: set[str] = set()

    for tool in report.discovered_tools:
        action = str(tool.get("name") or "agent.action")
        if action in seen_actions:
            continue
        seen_actions.add(action)

        risk = str(tool.get("risk") or "low").lower()
        desc = str(tool.get("description") or f"Discovered tool {action}")

        if risk == "critical":
            rules.append(
                {
                    "id": f"halt-{action.replace('.', '-')}",
                    "action": action,
                    "effect": "halt",
                    "reason": (
                        f"Critical side-effect tool ({action}) requires human "
                        "escalation before execution."
                    ),
                }
            )
        elif risk == "high":
            rules.append(
                {
                    "id": f"deny-{action.replace('.', '-')}",
                    "action": action,
                    "effect": "deny",
                    "reason": (
                        f"High-risk mutation/MCP tool ({action}) denied by default "
                        "until explicitly scoped."
                    ),
                }
            )
        else:
            capabilities.append({"name": action, "description": desc})
            rules.append(
                {
                    "id": f"allow-{action.replace('.', '-')}",
                    "action": action,
                    "effect": "allow",
                    "reason": f"Pre-approved low-risk tool ({action})",
                    "conditions": {"max_input_bytes": 65536},
                }
            )

    if not capabilities:
        capabilities.append(
            {
                "name": "kb.search",
                "description": "Default read-only capability placeholder",
            }
        )
        if "kb.search" not in seen_actions:
            rules.insert(
                0,
                {
                    "id": "allow-kb-search",
                    "action": "kb.search",
                    "effect": "allow",
                    "reason": "Read-only search capability",
                    "conditions": {"max_input_bytes": 65536},
                },
            )

    rules.append(
        {
            "id": "deny-everything-else",
            "action": "*",
            "effect": "deny",
            "reason": "Fail-closed default deny generated by agentproof scan.",
        }
    )

    return {
        "version": 1,
        "subject": subject,
        "capabilities": capabilities,
        "rules": rules,
    }


def save_starter_policy(
    report: ScanReport,
    path: str | Path,
    *,
    subject: str = "discovered-agent-system",
) -> Path:
    doc = generate_starter_policy(report, subject=subject)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return out


def scan_code_snippet(
    content: str,
    *,
    filename: str = "mcp.json",
    subject: str = "web-scanned-agent",
) -> dict[str, Any]:
    """Scan an in-memory ``mcp.json`` or ``agent_tools.py`` snippet from the web UI."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        safe_name = Path(filename).name or "mcp.json"
        target_file = tmp_path / safe_name
        target_file.write_text(content, encoding="utf-8")
        report = run_workspace_scan(tmp_path)
        policy_doc = generate_starter_policy(report, subject=subject)
        policy_yaml = yaml.safe_dump(policy_doc, sort_keys=False, allow_unicode=True)
        return {
            "report": report.to_dict(),
            "starter_policy_yaml": policy_yaml,
        }

"""Automated Lead Discovery, Risk Triage & Outreach Generator for AgentProof Cloud.

Turns ``agentproof scan`` into a repeatable B2B growth engine:
1. Scans either local repository checkouts or public GitHub repositories for
   Shadow MCP servers and unguarded Python agent tools.
2. Ranks targets by exposure ``risk_score`` (CRITICAL/HIGH findings first).
3. Emits for every qualified lead:
   - ``audit-report.md`` (concise security findings with exact locations)
   - ``policy.yaml`` (ready-to-commit fail-closed starter policy)
   - ``outreach.md`` (ready-to-send GitHub Issue & CTO cold email)
4. Exports ``pipeline.csv`` and ``pipeline.json`` for systematic daily outreach.
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..scanner.report import (
    ScanReport,
    generate_starter_policy,
    run_workspace_scan,
    save_starter_policy,
    scan_code_snippet,
)


@dataclass
class LeadCandidate:
    repo_name: str
    source_url: str
    risk_score: int
    security_grade: str
    critical_count: int
    high_count: int
    findings_count: int
    top_finding: str
    output_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "source_url": self.source_url,
            "risk_score": self.risk_score,
            "security_grade": self.security_grade,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings_count": self.findings_count,
            "top_finding": self.top_finding,
            "output_dir": self.output_dir,
        }


@dataclass
class ScoutSummary:
    scanned_count: int
    qualified_count: int
    output_dir: str
    leads: list[LeadCandidate] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_count": self.scanned_count,
            "qualified_count": self.qualified_count,
            "output_dir": self.output_dir,
            "leads": [lead.to_dict() for lead in self.leads],
        }


def _slugify(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-") or "repo"


def build_outreach_package(
    repo_name: str,
    report: ScanReport,
    out_dir: str | Path,
    *,
    source_url: str = "",
    website_url: str = "https://neon-sawine-352869.netlify.app",
) -> LeadCandidate:
    """Write audit report, starter policy, and outreach templates for one lead."""
    lead_dir = Path(out_dir) / _slugify(repo_name)
    lead_dir.mkdir(parents=True, exist_ok=True)

    # 1. Starter policy.yaml
    policy_path = save_starter_policy(
        report,
        lead_dir / "policy.yaml",
        subject=_slugify(repo_name),
    )

    # 2. Concise technical audit report
    critical_count = sum(1 for f in report.findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in report.findings if f.severity.value == "HIGH")
    findings_md = "\n".join(
        f"- **[{f.severity.value}] `{f.rule_id}`** (`{f.location}`): {f.title} — {f.remediation}"
        for f in report.findings[:8]
    )
    audit_md = f"""# Automated AI Agent & MCP Security Audit — `{repo_name}`

- **Source**: {source_url or report.target}
- **Scanned At**: {report.scanned_at}
- **Exposure Risk Score**: **{report.risk_score}/100 (Grade: {report.security_grade})**
- **Findings**: {len(report.findings)} total ({critical_count} CRITICAL, {high_count} HIGH)

## Key Findings

{findings_md}

## 1-Minute Fix

We generated a fail-closed starter [`policy.yaml`](./policy.yaml) for your tools.
Install the MIT-licensed scanner locally to verify:

```bash
pip install agentproof
agentproof scan . --init-policy policy.yaml
```
"""
    (lead_dir / "audit-report.md").write_text(audit_md, encoding="utf-8")

    # 3. Ready-to-send English outreach (GitHub Issue + CTO Cold Email)
    top_finding = report.findings[0].title if report.findings else "Unguarded agent surface"
    outreach_md = f"""# Ready-to-Send Outreach — `{repo_name}`

## Option A: GitHub Issue / PR Comment (Non-spammy, value-first)

**Title:** Security heads-up: {len(report.findings)} unguarded MCP / agent tool finding(s) (auto-generated starter `policy.yaml` included)

Hi maintainers,

While running automated static checks across open-source AI agent stacks, we noticed `{repo_name}` exposes **{len(report.findings)} unguarded tool/MCP path(s)** (Risk Score: **{report.risk_score}/100**, e.g. *{top_finding}*).

Here is the summary:
{findings_md}

I attached a ready-to-use, fail-closed `policy.yaml` generated via the MIT-licensed `agentproof scan` CLI (works 100% offline, no telemetry):
- Live browser scanner (no install): {website_url}
- Full pre-execution receipt & SOC 2 / EU AI Act Art.26 evidence pack: `pip install agentproof`

Hope this helps harden your agent pipeline!

---

## Option B: Cold Email to Founder / CTO

**Subject:** Quick heads-up on {repo_name} ({critical_count} critical MCP/agent gate gaps) + fix attached

Hi [First Name],

Our static scanner flagged `{repo_name}` ({report.risk_score}/100 risk score) — specifically `{top_finding}` runs without a pre-execution policy gate or signed audit trail.

I already generated a drop-in `policy.yaml` for your repo so you can enforce fail-closed rules in 60 seconds (attached).

If enterprise customers are asking you for **SOC 2 / ISO 42001 / EU AI Act Art. 26 tamper-evident AI audit logs** (or syncing agent controls into **Vanta / Drata / Datadog**), you can also try AgentProof Cloud's out-of-band Witness Notary at {website_url} ($99/mo Pro or free OSS CLI).

Happy to send over the exact remediation diff if helpful.

Best,
AgentProof Security Team
"""
    (lead_dir / "outreach.md").write_text(outreach_md, encoding="utf-8")
    _ = policy_path

    return LeadCandidate(
        repo_name=repo_name,
        source_url=source_url or report.target,
        risk_score=report.risk_score,
        security_grade=report.security_grade,
        critical_count=critical_count,
        high_count=high_count,
        findings_count=len(report.findings),
        top_finding=top_finding,
        output_dir=str(lead_dir),
    )


def _write_pipeline_files(summary: ScoutSummary) -> None:
    out = Path(summary.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary.leads.sort(
        key=lambda item: (-item.risk_score, -item.critical_count, item.repo_name)
    )
    (out / "pipeline.json").write_text(
        json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    with (out / "pipeline.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "repo_name",
                "risk_score",
                "grade",
                "critical",
                "high",
                "total_findings",
                "top_finding",
                "source_url",
                "outreach_bundle_dir",
            ]
        )
        for lead in summary.leads:
            writer.writerow(
                [
                    lead.repo_name,
                    lead.risk_score,
                    lead.security_grade,
                    lead.critical_count,
                    lead.high_count,
                    lead.findings_count,
                    lead.top_finding,
                    lead.source_url,
                    lead.output_dir,
                ]
            )


def scout_local_repositories(
    root_dir: str | Path,
    *,
    out_dir: str | Path = "leads",
    min_risk_score: int = 1,
    website_url: str = "https://neon-sawine-352869.netlify.app",
) -> ScoutSummary:
    """Scan every subdirectory (or single workspace) under ``root_dir`` and build lead bundles."""
    root = Path(root_dir)
    subdirs = [p for p in sorted(root.iterdir()) if p.is_dir() and not p.name.startswith(".")]
    targets = subdirs if subdirs else [root]

    leads: list[LeadCandidate] = []
    for target in targets:
        report = run_workspace_scan(target)
        if report.risk_score >= min_risk_score and report.findings:
            leads.append(
                build_outreach_package(
                    target.name,
                    report,
                    out_dir,
                    source_url=str(target),
                    website_url=website_url,
                )
            )

    summary = ScoutSummary(
        scanned_count=len(targets),
        qualified_count=len(leads),
        output_dir=str(out_dir),
        leads=leads,
    )
    _write_pipeline_files(summary)
    return summary


def discover_github_leads(
    *,
    query: str = "filename:mcp.json mcpServers",
    limit: int = 15,
    out_dir: str | Path = "leads",
    github_token: str | None = None,
    min_risk_score: int = 1,
    website_url: str = "https://neon-sawine-352869.netlify.app",
) -> ScoutSummary:
    """Search public GitHub code via REST API, scan matching configs, and emit outreach bundles."""
    token = (
        github_token
        if github_token is not None
        else os.environ.get("GITHUB_TOKEN", "").strip()
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agentproof-scout/0.2.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    encoded_q = urllib.parse.quote(query)
    api_url = f"https://api.github.com/search/code?q={encoded_q}&per_page={min(max(1, limit), 30)}"
    req = urllib.request.Request(api_url, headers=headers, method="GET")

    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        payload = json.loads(resp.read().decode("utf-8"))

    items = payload.get("items") or []
    leads: list[LeadCandidate] = []
    scanned = 0

    for item in items[:limit]:
        repo = (item.get("repository") or {}).get("full_name") or "unknown/repo"
        html_url = str(item.get("html_url") or f"https://github.com/{repo}")
        file_path = str(item.get("path") or "mcp.json")
        # Convert GitHub blob HTML URL or API URL to raw file content URL
        raw_url = (
            html_url.replace("https://github.com/", "https://raw.githubusercontent.com/")
            .replace("/blob/", "/")
        )
        try:
            raw_req = urllib.request.Request(raw_url, headers={"User-Agent": "agentproof-scout/0.2.0"})
            with urllib.request.urlopen(raw_req, timeout=10) as raw_resp:  # noqa: S310
                content = raw_resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError):
            continue

        scanned += 1
        res = scan_code_snippet(
            content,
            filename=Path(file_path).name or "mcp.json",
            subject=_slugify(repo),
        )
        report_dict = res["report"]
        report_obj = _report_from_dict(report_dict)
        if report_obj.risk_score >= min_risk_score and report_obj.findings:
            leads.append(
                build_outreach_package(
                    repo,
                    report_obj,
                    out_dir,
                    source_url=html_url,
                    website_url=website_url,
                )
            )

    summary = ScoutSummary(
        scanned_count=scanned,
        qualified_count=len(leads),
        output_dir=str(out_dir),
        leads=leads,
    )
    _write_pipeline_files(summary)
    return summary


def _report_from_dict(data: dict[str, Any]) -> ScanReport:
    from ..scanner.report import Finding, Severity

    findings = [
        Finding(
            rule_id=f["rule_id"],
            severity=Severity(f["severity"]),
            category=f["category"],
            location=f["location"],
            title=f["title"],
            detail=f["detail"],
            remediation=f["remediation"],
            action_name=f.get("action_name", ""),
        )
        for f in data.get("findings", [])
    ]
    return ScanReport(
        target=data.get("target", ""),
        scanned_at=data.get("scanned_at", _dt.datetime.now(_dt.timezone.utc).isoformat()),
        risk_score=int(data.get("risk_score", 0)),
        security_grade=str(data.get("security_grade", "A")),
        findings=findings,
        discovered_tools=list(data.get("discovered_tools", [])),
        summary=dict(data.get("summary", {})),
    )

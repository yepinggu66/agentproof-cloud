"""MCP configuration scanner for Shadow AI and over-privileged MCP servers.

Discovery (which config files exist, which servers/tools they declare) stays
here because the workspace report needs that inventory for starter-policy
generation. **Finding detection is delegated to the one canonical engine**
(:mod:`agentproof.scanner.engine`), so the CLI, the web API and the browser
port cannot drift apart in their MCP rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core._textio import TextDecodeError, read_text
from . import engine

MCP_CONFIG_PATTERNS = (
    "mcp.json",
    "*mcp*.json",
    "claude_desktop_config.json",
)

# Legacy workspace-report rule ids kept for API compatibility. The canonical
# engine emits MCP-NN ids; this maps them onto the historical MCP-00N names.
LEGACY_RULE_IDS = {
    "MCP-12": "MCP-001",  # unpinned npx -y
    "MCP-03": "MCP-002",  # shell interpreter
    "MCP-04": "MCP-002",  # shell/command server
    "MCP-07": "MCP-003",  # broad filesystem root
    "MCP-05": "MCP-004",  # plaintext credential
}

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def is_mcp_config_file(path: Path) -> bool:
    name = path.name.lower()
    if name in ("mcp.json", "claude_desktop_config.json", "mcp_config.json"):
        return True
    if "mcp" in name and name.endswith(".json"):
        return True
    return False


def _server_from_detail(detail: str) -> str:
    """Engine findings prefix their detail with ``[server]``."""
    if detail.startswith("[") and "]" in detail:
        return detail[1 : detail.index("]")]
    return "mcp.json"


def scan_mcp_configs(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(findings, discovered_tools)`` for every MCP config under root."""
    findings: list[dict[str, Any]] = []
    discovered_tools: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    if root.is_file():
        candidates = [root] if is_mcp_config_file(root) else []
    else:
        candidates = [
            p
            for p in root.rglob("*.json")
            if is_mcp_config_file(p)
            and not any(
                part in (".git", "node_modules", ".venv", "venv", "__pycache__")
                for part in p.parts
            )
        ]

    for config_path in sorted(candidates):
        try:
            text = read_text(config_path, kind="MCP config")
            data = json.loads(text)
        except (TextDecodeError, ValueError, OSError):
            continue
        if not isinstance(data, dict):
            continue

        servers = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers, dict):
            continue

        rel_path = _rel(config_path, root)
        for server_name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            action_name = f"mcp.{server_name}"
            cmd = str(spec.get("command") or "").strip()
            discovered_tools.append(
                {
                    "name": action_name,
                    "source": rel_path,
                    "kind": "mcp_server",
                    "risk": "high",
                    "description": f"MCP server '{server_name}' ({cmd})",
                }
            )

        try:
            result = engine.scan_mcp(text, subject=str(config_path))
        except engine.ScanInputError:
            continue

        for finding in result.findings:
            server_name = _server_from_detail(finding.detail)
            rule_id = LEGACY_RULE_IDS.get(finding.id, finding.id)
            key = (rule_id, server_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": SEVERITY_MAP.get(finding.severity, "MEDIUM"),
                    "category": "shadow_mcp",
                    "location": f"{rel_path}:{server_name}",
                    "title": finding.title,
                    "detail": finding.detail,
                    "remediation": finding.remediation,
                    "action_name": f"mcp.{server_name}" if server_name != "mcp.json" else "",
                }
            )

    return findings, discovered_tools


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")

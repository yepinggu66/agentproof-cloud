"""MCP configuration scanner for Shadow AI and over-privileged MCP servers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..core._textio import TextDecodeError, read_text

MCP_CONFIG_PATTERNS = (
    "mcp.json",
    "*mcp*.json",
    "claude_desktop_config.json",
)

DANGEROUS_COMMANDS = {
    "bash",
    "sh",
    "zsh",
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
}

SECRET_KEY_RE = re.compile(
    r"(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|ACCESS_KEY|AUTH)",
    re.IGNORECASE,
)


def is_mcp_config_file(path: Path) -> bool:
    name = path.name.lower()
    if name in ("mcp.json", "claude_desktop_config.json", "mcp_config.json"):
        return True
    if "mcp" in name and name.endswith(".json"):
        return True
    return False


def scan_mcp_configs(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scan ``root`` for MCP server definitions and return (findings, discovered_tools).

    Returns raw dicts converted into :class:`Finding` objects by ``report.py``.
    """
    findings: list[dict[str, Any]] = []
    discovered_tools: list[dict[str, Any]] = []

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
            args = [str(a) for a in (spec.get("args") or []) if a is not None]
            env = spec.get("env") if isinstance(spec.get("env"), dict) else {}

            discovered_tools.append(
                {
                    "name": action_name,
                    "source": rel_path,
                    "kind": "mcp_server",
                    "risk": "high",
                    "description": f"MCP server '{server_name}' ({cmd})",
                }
            )

            # 1. Check for unpinned npx -y / uvx remote code execution
            cmd_base = Path(cmd).name.lower()
            if cmd_base in ("npx", "npx.cmd") and ("-y" in args or "--yes" in args):
                pkg = next((a for a in args if not a.startswith("-")), "<unknown>")
                if "@" not in pkg.lstrip("@"):
                    findings.append(
                        {
                            "rule_id": "MCP-001",
                            "severity": "HIGH",
                            "category": "shadow_mcp",
                            "location": f"{rel_path}:{server_name}",
                            "title": f"Unpinned auto-install MCP server '{server_name}'",
                            "detail": (
                                f"Server '{server_name}' runs `{cmd} {' '.join(args)}` "
                                "without pinning an immutable version or digest, "
                                "exposing the agent to supply-chain poisoning."
                            ),
                            "remediation": (
                                f"Pin `{pkg}` to an exact version and gate `mcp.{server_name}.*` "
                                "in policy.yaml."
                            ),
                            "action_name": action_name,
                        }
                    )

            # 2. Check for raw shell execution MCP servers
            if cmd_base in DANGEROUS_COMMANDS or any(
                "shell" in a.lower() or "exec" in a.lower() for a in [server_name, *args]
            ):
                findings.append(
                    {
                        "rule_id": "MCP-002",
                        "severity": "CRITICAL",
                        "category": "shadow_mcp",
                        "location": f"{rel_path}:{server_name}",
                        "title": f"Unrestricted shell/command MCP server '{server_name}'",
                        "detail": (
                            f"MCP server '{server_name}' exposes shell or command execution "
                            f"(`{cmd}`) without an agentproof pre-execution receipt gate."
                        ),
                        "remediation": (
                            f"Add rule `id: halt-{server_name}` with `effect: halt` or "
                            "`effect: deny` in policy.yaml."
                        ),
                        "action_name": action_name,
                    }
                )

            # 3. Check for broad filesystem access
            for arg in args:
                norm_arg = arg.strip()
                if norm_arg in ("/", "C:\\", "C:/", "..", "~"):
                    findings.append(
                        {
                            "rule_id": "MCP-003",
                            "severity": "CRITICAL",
                            "category": "shadow_mcp",
                            "location": f"{rel_path}:{server_name}",
                            "title": f"Root/home filesystem mounted into MCP server '{server_name}'",
                            "detail": (
                                f"Argument `{norm_arg}` grants broad host filesystem access "
                                f"to MCP server '{server_name}'."
                            ),
                            "remediation": (
                                "Restrict filesystem MCP server arguments to an isolated "
                                "workspace directory and enforce max_input_bytes in policy.yaml."
                            ),
                            "action_name": action_name,
                        }
                    )

            # 4. Check for hardcoded plaintext credentials in env
            for env_key, env_val in env.items():
                val_str = str(env_val or "").strip()
                if (
                    SECRET_KEY_RE.search(str(env_key))
                    and val_str
                    and not val_str.startswith("${")
                    and not val_str.startswith("$")
                    and val_str != "<REDACTED>"
                ):
                    findings.append(
                        {
                            "rule_id": "MCP-004",
                            "severity": "HIGH",
                            "category": "shadow_mcp",
                            "location": f"{rel_path}:{server_name}.env.{env_key}",
                            "title": f"Hardcoded credential `{env_key}` in MCP config",
                            "detail": (
                                f"Plaintext secret found in `{rel_path}` under "
                                f"server '{server_name}' environment variable `{env_key}`."
                            ),
                            "remediation": (
                                "Inject secrets via environment references (`${ENV_VAR}`) "
                                "and scope tool access with `required_scopes` in policy.yaml."
                            ),
                            "action_name": action_name,
                        }
                    )

    return findings, discovered_tools


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")

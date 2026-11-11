"""Static and configuration scanner for Shadow MCP servers and unguarded agent tools.

This module powers ``agentproof scan`` — the zero-config discovery wedge that
finds:
1. **Shadow MCP Servers** in ``mcp.json``, ``claude_desktop_config.json``,
   ``.cursor/mcp.json``, ``.vscode/mcp.json``, etc., flagging unpinned remote
   execution (``npx -y``), unrestricted shell/filesystem access, and hardcoded
   secrets in environment blocks.
2. **Unguarded Agent Tools** in Python source files via AST analysis: functions
   decorated as agent tools or performing high-risk side effects (subprocess,
   network, database mutations, file writes/deletes) without an ``agentproof``
   pre-execution policy gate.
3. **Starter Policy Generation** (``--init-policy``): synthesizes a fail-closed
   ``policy.yaml`` directly from discovered tools so developers can lock down
   their agent in seconds.
"""

from __future__ import annotations

from .mcp_scanner import scan_mcp_configs
from .python_scanner import scan_python_files
from .report import (
    Finding,
    ScanReport,
    Severity,
    generate_starter_policy,
    run_workspace_scan,
)
from .engine import (
    ScanInputError,
    ScanResult,
    scan_document,
    scan_mcp_document,
    scan_python_document,
)

__all__ = [
    "Finding",
    "ScanReport",
    "Severity",
    "ScanInputError",
    "ScanResult",
    "generate_starter_policy",
    "run_workspace_scan",
    "scan_document",
    "scan_mcp_document",
    "scan_python_document",
    "scan_mcp_configs",
    "scan_python_files",
]

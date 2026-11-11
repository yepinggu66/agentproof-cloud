"""One document scanner: the web API, the library and the audit tools agree.

The scanner implementation moved from ``server/scan.py`` to
``agentproof.scanner.engine``. These tests pin the single-source property so a
future refactor cannot quietly reintroduce a second rule copy.
"""

from __future__ import annotations

import agentproof.scanner.engine as engine
import server.scan as server_scan
from agentproof.scanner import scan_document


def test_server_scan_is_the_package_engine():
    assert server_scan.scan is engine.scan
    assert server_scan.ScanInputError is engine.ScanInputError
    assert scan_document is engine.scan


def test_engine_grade_matches_previous_server_contract(sample_texts):
    from_server = server_scan.scan("mcp", sample_texts["danger_mcp"])
    from_library = scan_document("mcp", sample_texts["danger_mcp"])
    assert from_server.grade == from_library.grade == "F"
    assert [f.id for f in from_server.findings] == [f.id for f in from_library.findings]
    assert from_server.policy_yaml == from_library.policy_yaml


def test_workspace_scan_mcp_findings_come_from_the_engine(tmp_path):
    """The AST workspace report delegates MCP detection to the canonical engine."""
    import json

    from agentproof.scanner import run_workspace_scan

    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "shell": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-shell", "/"],
                        "env": {"OPENAI_API_KEY": "sk-live-plaintext-secret-12345"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = run_workspace_scan(tmp_path)
    ids = {finding.rule_id for finding in report.findings}
    # legacy ids are preserved, but produced by engine.scan_mcp
    assert {"MCP-001", "MCP-002", "MCP-003", "MCP-004"}.issubset(ids)

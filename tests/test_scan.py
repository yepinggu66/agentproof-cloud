"""Scanner unit tests: grades, findings, policy rendering and determinism."""

from __future__ import annotations

import json

import pytest
import yaml

from server.scan import MAX_CONTENT_BYTES, ScanInputError, scan


def test_dangerous_mcp_config_gets_f(sample_texts):
    result = scan("mcp", sample_texts["danger_mcp"])
    assert result.grade == "F"
    assert result.score == 100
    assert len(result.findings) >= 6
    severities = {finding.severity for finding in result.findings}
    assert {"critical", "high"}.issubset(severities)
    ids = {finding.id for finding in result.findings}
    assert {"MCP-02", "MCP-03", "MCP-05", "MCP-07", "MCP-09", "MCP-10"}.issubset(ids)
    # the production password must never be echoed back in the report
    joined = json.dumps([finding.as_dict() for finding in result.findings], ensure_ascii=False)
    assert "Pr0d%21Pass" not in joined


def test_safe_mcp_config_gets_a(sample_texts):
    result = scan("mcp", sample_texts["safe_mcp"])
    assert result.grade == "A"
    assert result.score == 0
    assert result.findings == []


def test_python_agent_sample_is_flagged(sample_texts):
    result = scan("python", sample_texts["python"])
    assert result.kind == "python"
    assert result.grade == "F"
    ids = {finding.id for finding in result.findings}
    for expected in ("PY-01", "PY-03", "PY-05", "PY-07", "PY-08", "PY-09", "PY-11", "PY-16", "PY-17"):
        assert expected in ids, f"missing {expected} in {sorted(ids)}"
    assert "tool.refund" in result.capabilities
    assert "tool.run_shell" in result.capabilities


@pytest.mark.parametrize(
    "text,kind,expected_grade",
    [
        ('{"mcpServers": {}}', "mcp", "A"),
        ('{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg"]}}}', "mcp", "B"),
        ('{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "pkg", "/"], "autoApprove": true}}}', "mcp", "F"),
    ],
)
def test_grades_are_monotonic(text, kind, expected_grade):
    assert scan(kind, text).grade == expected_grade


def test_generated_policy_is_valid_yaml_and_deny_by_default(sample_texts):
    result = scan("mcp", sample_texts["danger_mcp"])
    document = yaml.safe_load(result.policy_yaml)
    assert document["version"] == 1
    assert document["mode"] == "enforce"
    assert document["audit"]["sign_before_action"] is True
    assert document["capabilities"], "capabilities must be declared"
    rules = document["rules"]
    last = rules[-1]
    assert last["id"] == "deny-default"
    assert last["action"] == "*"
    assert last["effect"] == "deny"
    # no allow-all shortcut may survive when critical findings exist
    for rule in rules:
        if rule.get("effect") == "allow":
            assert rule.get("action") != "*", "critical finding must not keep a wildcard allow"
    assert all("id" in rule and "effect" in rule for rule in rules)


def test_scan_is_deterministic(sample_texts):
    first = scan("mcp", sample_texts["danger_mcp"]).policy_yaml
    second = scan("mcp", sample_texts["danger_mcp"]).policy_yaml
    assert first == second


def test_jsonc_comments_and_trailing_commas_are_tolerated():
    text = '{\n  // local override\n  "mcpServers": {\n    "kb": {"command": "npx", "args": ["-y", "@acme/kb@1.0.0"],},\n  },\n}'
    result = scan("mcp", text)
    assert result.grade == "A"
    assert result.stats["servers"] == 1


def test_invalid_json_raises_actionable_error():
    with pytest.raises(ScanInputError) as excinfo:
        scan("mcp", "{ this is not json")
    message = str(excinfo.value)
    assert "mcp.json" in message
    assert "JSON" in message


def test_unknown_kind_rejected():
    with pytest.raises(ScanInputError):
        scan("yaml", "version: 1")


def test_empty_input_rejected():
    with pytest.raises(ScanInputError):
        scan("python", "   \n  ")
    with pytest.raises(ScanInputError):
        scan("mcp", "")


def test_oversized_input_rejected():
    with pytest.raises(ScanInputError):
        scan("python", "x" * (MAX_CONTENT_BYTES + 10))


def test_secret_paths_and_unpinned_versions():
    text = json.dumps(
        {
            "mcpServers": {
                "sync": {
                    "command": "npx",
                    "args": ["-y", "mcp-sync", "~/.ssh/id_rsa"],
                }
            }
        }
    )
    result = scan("mcp", text)
    ids = {finding.id for finding in result.findings}
    assert "MCP-08" in ids or "MCP-07" in ids
    assert "MCP-12" in ids

"""Tests for the signed audit report generator."""

from __future__ import annotations

import json
from pathlib import Path

from tools.audit_report import AuditResult, load_or_create_key, redact, render_html, sign_result, verify_report


def test_redact_masks_secrets():
    text = "sk-abcdefghijklmnop and postgres://user:secret@db/x"
    cleaned = redact(text)
    assert "sk-abcdefghijklmnop" not in cleaned
    assert "user:secret@" not in cleaned


def test_report_signature_roundtrip(tmp_path):
    result = AuditResult(client="Acme", prepared_by="AgentProof.cloud", generated_at="2026-11-11T00:00:00Z")
    result.findings = [
        {"id": "MCP-03", "severity": "critical", "title": "shell", "detail": "d",
         "evidence": "bash -c", "remediation": "fix", "source": "mcp.json"},
    ]
    result.files = [{"path": "mcp.json", "name": "mcp.json", "kind": "mcp", "grade": "F", "score": 80, "findings": 1}]
    result.grade = "F"
    result.score = 80

    private_pem, public_pem = load_or_create_key(tmp_path / "key.pem")
    signature = sign_result(result, private_pem, public_pem)
    report = {"result": result.__dict__, "signature": signature}

    assert verify_report(report, public_pem) is True

    report["result"]["grade"] = "A"
    assert verify_report(report, public_pem) is False


def test_html_report_is_self_contained():
    result = AuditResult(client="Acme", prepared_by="AgentProof.cloud", generated_at="2026-11-11T00:00:00Z")
    signature = {
        "digest": "0" * 64,
        "signature": "1" * 128,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
        "fingerprint": "2" * 64,
        "signed_at": "2026-11-11T00:00:00Z",
    }
    html = render_html(result, signature)
    assert "AgentProof.cloud" in html
    assert "报告完整性" in html
    assert "http://" not in html and "https://" not in html
    json.dumps({"ok": True})  # keep the import used

"""Tests for the lead-generation helper (offline parts only)."""

from __future__ import annotations

from tools.leadgen import RepoReport, python_is_interesting, redact, render_report


def test_redact_removes_secret_lookalikes():
    text = "key=sk-abcdefghijklmnopqrstuvwxyz token=ghp_abcdefghijklmnop and postgres://user:secret@db/x"
    cleaned = redact(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert "ghp_abcdefghijklmnop" not in cleaned
    assert "user:secret@" not in cleaned
    assert "***redacted***" in cleaned


def test_python_is_interesting():
    assert python_is_interesting("@tool\ndef run_shell(cmd): ...")
    assert python_is_interesting("subprocess.run(cmd)")
    assert not python_is_interesting("def add(a, b):\n    return a + b\n")


def test_render_report_contains_disclaimer_and_grade():
    report = RepoReport(
        full_name="acme/agent",
        url="https://github.com/acme/agent",
        stars=12,
        license="MIT",
        description="demo",
        grade="D",
        findings=3,
        critical=1,
        scans=[
            {
                "path": "mcp.json",
                "kind": "mcp",
                "grade": "D",
                "score": 46,
                "findings": 3,
                "critical": 1,
                "high": 0,
                "top_findings": [
                    {
                        "id": "MCP-03",
                        "severity": "critical",
                        "title": "shell 启动",
                        "detail": "detail",
                        "evidence": "bash -c",
                        "remediation": "fix it",
                    }
                ],
                "policy_yaml": "version: 1\nsubject: acme",
            }
        ],
        top=[
            {
                "id": "MCP-03",
                "severity": "critical",
                "title": "shell 启动",
                "evidence": "bash -c",
                "remediation": "fix it",
                "path": "mcp.json",
            }
        ],
    )
    text = render_report(report, "2026-11-11T00:00:00Z")
    assert "acme/agent" in text
    assert "**D**" in text
    assert "不是漏洞证明" in text
    assert "反馈" in text

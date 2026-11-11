"""End-to-end: the full workflow a user actually runs.

    keygen → policy-check → chain-new → chain-append → chain-seal
           → verify → record → genregress → replay → aibom → evidence

This file exercises the CLI end to end so that the documented workflow is
known to work, not just the individual units.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from agentproof.cli import main


def _run(runner: CliRunner, *args):
    result = runner.invoke(main, list(args))
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result


def test_full_workflow(tmp_path):
    runner = CliRunner()
    workdir = tmp_path

    # --- keys ---------------------------------------------------------
    result = _run(runner, "keygen", "-d", str(workdir), "-n", "demo")
    assert result.exit_code == 0
    assert (workdir / "demo.key").exists()
    assert (workdir / "demo.pub").exists()

    key = str(workdir / "demo.key")
    chain_path = str(workdir / "chain.json")

    # --- policy -------------------------------------------------------
    policy_path = workdir / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "subject": "acme-support-agent",
                "capabilities": [
                    {"name": "kb.search"},
                    {"name": "order.refund"},
                ],
                "rules": [
                    {
                        "id": "allow-kb",
                        "action": "kb.search",
                        "effect": "allow",
                        "reason": "Read-only KB access is pre-approved",
                    },
                    {
                        "id": "deny-db-write",
                        "action": "db.write",
                        "effect": "deny",
                        "reason": "Writes to the customer database are not permitted",
                    },
                    {
                        "id": "deny-default",
                        "action": "*",
                        "effect": "deny",
                        "reason": "Default deny",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    allowed = _run(
        runner, "policy-check", str(policy_path), "-a", "kb.search", "--input", '{"q":"x"}'
    )
    assert allowed.exit_code == 0
    assert "ALLOW" in allowed.output

    denied = _run(runner, "policy-check", str(policy_path), "-a", "db.write")
    assert denied.exit_code == 1
    assert "DENY" in denied.output

    # --- chain --------------------------------------------------------
    created = _run(
        runner, "chain-new", chain_path, "-k", key, "-s", "acme-support-agent"
    )
    assert created.exit_code == 0

    appended = _run(
        runner,
        "chain-append",
        chain_path,
        "-k",
        key,
        "--actor",
        "support-agent",
        "--action",
        "kb.search",
        "--decision",
        "ALLOW",
        "--reason",
        "Read-only KB access is pre-approved",
        "--policy-id",
        "pol-1",
        "--policy-digest",
        "pd-1",
        "--inputs-digest",
        "id-1",
    )
    assert appended.exit_code == 0
    assert "appended seq 0" in appended.output

    _run(
        runner,
        "chain-append",
        chain_path,
        "-k",
        key,
        "--actor",
        "support-agent",
        "--action",
        "db.write",
        "--decision",
        "DENY",
        "--reason",
        "Action was never declared as a capability",
        "--policy-id",
        "pol-1",
        "--policy-digest",
        "pd-1",
        "--inputs-digest",
        "id-2",
    )

    sealed = _run(
        runner, "chain-seal", chain_path, "-k", key, "--out", str(workdir / "seal.json")
    )
    assert sealed.exit_code == 0
    assert (workdir / "seal.json").exists()

    # --- verify -------------------------------------------------------
    verified = _run(runner, "verify", chain_path)
    assert verified.exit_code == 0
    assert "PASS" in verified.output

    # tamper, then verify again
    data = json.loads(Path(chain_path).read_text(encoding="utf-8"))
    data["records"][1]["reason"] = "Looks fine to me"
    Path(chain_path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    tampered = _run(runner, "verify", chain_path)
    assert tampered.exit_code == 1
    assert "FAIL" in tampered.output

    # restore
    data["records"][1]["reason"] = "Action was never declared as a capability"
    Path(chain_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    assert _run(runner, "verify", chain_path).exit_code == 0

    # --- record -------------------------------------------------------
    raw_path = workdir / "raw.jsonl"
    raw_path.write_text(
        "\n".join(
            [
                json.dumps({"type": "agent_start", "agent": "support-agent"}),
                json.dumps(
                    {
                        "type": "tool_call",
                        "agent": "support-agent",
                        "name": "kb.search",
                        "input": {"q": "refund policy"},
                    }
                ),
                json.dumps(
                    {
                        "type": "tool_call",
                        "agent": "support-agent",
                        "name": "db.write",
                        "input": {"sql": "UPDATE customers SET ..."},
                    }
                ),
                json.dumps(
                    {
                        "type": "error",
                        "agent": "support-agent",
                        "name": "db.write",
                        "error": "permission denied",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    trace_path = str(workdir / "trace.jsonl")
    recorded = _run(
        runner, "record", trace_path, "--adapter", "generic", "--input", str(raw_path)
    )
    assert recorded.exit_code == 0
    assert Path(trace_path).exists()

    # --- genregress ---------------------------------------------------
    generated = _run(runner, "genregress", trace_path, "-d", str(workdir / "cases"))
    assert generated.exit_code == 0
    case_files = list((workdir / "cases").glob("*.yaml"))
    assert len(case_files) == 1

    case = yaml.safe_load(case_files[0].read_text(encoding="utf-8"))
    assert len(case["steps"]) == 2
    assert case["steps"][0]["action"] == "kb.search"

    # --- replay -------------------------------------------------------
    replayed = _run(runner, "replay", str(case_files[0]))
    assert replayed.exit_code == 0
    assert "PASS" in replayed.output

    # --- aibom --------------------------------------------------------
    aibom = _run(
        runner, "aibom", trace_path, "-d", str(workdir), "-s", "acme-support-agent"
    )
    assert aibom.exit_code == 0
    aibom_data = json.loads((workdir / "aibom.json").read_text(encoding="utf-8"))
    assert aibom_data["summary"]["agent_count"] == 1
    assert aibom_data["summary"]["tool_count"] == 2

    # --- evidence -----------------------------------------------------
    evidence = _run(runner, "evidence", chain_path, "-d", str(workdir / "evidence"))
    assert evidence.exit_code == 0

    pack = json.loads(
        (workdir / "evidence" / "evidence-pack.json").read_text(encoding="utf-8")
    )
    assert pack["verification"]["ok"] is True
    assert pack["summary"]["total_decisions"] == 2
    assert pack["summary"]["by_decision"]["ALLOW"] == 1
    assert pack["summary"]["by_decision"]["DENY"] == 1
    assert pack["limitations"]

    markdown = (workdir / "evidence" / "evidence-pack.md").read_text(encoding="utf-8")
    assert "Deployer evidence pack" in markdown
    assert "kb.search" in markdown


def test_verify_reports_failure_with_exit_code_one(tmp_path):
    runner = CliRunner()

    _run(runner, "keygen", "-d", str(tmp_path))
    key = str(tmp_path / "agentproof.key")
    chain_path = str(tmp_path / "chain.json")

    _run(runner, "chain-new", chain_path, "-k", key)
    _run(
        runner,
        "chain-append",
        chain_path,
        "-k",
        key,
        "--actor",
        "a",
        "--action",
        "x",
        "--decision",
        "ALLOW",
        "--reason",
        "r",
    )

    data = json.loads(Path(chain_path).read_text(encoding="utf-8"))
    data["records"][0]["reason"] = "changed"
    Path(chain_path).write_text(json.dumps(data), encoding="utf-8")

    result = _run(runner, "verify", chain_path)
    assert result.exit_code == 1


def test_chain_append_rejects_an_invalid_decision(tmp_path):
    runner = CliRunner()
    _run(runner, "keygen", "-d", str(tmp_path))
    key = str(tmp_path / "agentproof.key")
    chain_path = str(tmp_path / "chain.json")
    _run(runner, "chain-new", chain_path, "-k", key)

    result = runner.invoke(
        main,
        [
            "chain-append",
            chain_path,
            "-k",
            key,
            "--actor",
            "a",
            "--action",
            "x",
            "--decision",
            "MAYBE",
            "--reason",
            "r",
        ],
    )
    assert result.exit_code != 0

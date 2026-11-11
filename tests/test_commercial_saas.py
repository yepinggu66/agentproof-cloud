"""Tests for AgentProof v0.2.0 commercial SaaS modules:
1. Shadow MCP & Python AST Scanner (`agentproof.scanner`)
2. 1-line RuntimeGate Decorator (`agentproof.runtime`)
3. Lloyd's AIUC-1 Insurability Scorecard (`agentproof.evidence.insurability`)
4. Multi-Tenant Cloud Witness Notary, Quota & Billing Control Plane (`agentproof.cloud`)
"""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentproof.cli import main
from agentproof.cloud import (
    CloudNotary,
    CloudStorage,
    NotarizationError,
    QuotaExceededError,
    SubscriptionPlan,
    create_cloud_server,
    verify_witness_signature,
)
from agentproof.core.policy import load_policy
from agentproof.core.receipt import Decision
from agentproof.evidence import FRAMEWORK_MAPPINGS, compute_insurability_score
from agentproof.runtime import PolicyDeniedError, RuntimeGate
from agentproof.scanner import generate_starter_policy, run_workspace_scan


# ----------------------------------------------------------------------
# 1. Scanner (Shadow MCP + Python AST + Starter Policy Synthesis)
# ----------------------------------------------------------------------
def test_scanner_detects_shadow_mcp_and_unguarded_python_tools(tmp_path: Path) -> None:
    mcp_cfg = {
        "mcpServers": {
            "shell-runner": {
                "command": "npx",
                "args": ["-y", "mcp-server-shell", "/"],
                "env": {"OPENAI_API_KEY": "sk-live-plaintext-secret-12345"},
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(mcp_cfg), encoding="utf-8")

    py_code = '''
import os
import subprocess

def tool(fn):
    return fn

@tool
def nuke_production_db(user_id: str):
    """Delete a customer record and run cleanup."""
    subprocess.run(["rm", "-rf", "/tmp/cache"])
    sql = "DELETE FROM customers WHERE id = 1"
    return sql
'''
    (tmp_path / "agent_tools.py").write_text(py_code, encoding="utf-8")

    report = run_workspace_scan(tmp_path)
    rule_ids = {f.rule_id for f in report.findings}

    assert "MCP-001" in rule_ids  # unpinned npx -y
    assert "MCP-002" in rule_ids  # shell execution MCP
    assert "MCP-003" in rule_ids  # root / filesystem mount
    assert "MCP-004" in rule_ids  # hardcoded OPENAI_API_KEY
    assert "TOOL-000" in rule_ids  # unguarded @tool
    assert "TOOL-001" in rule_ids  # subprocess.run
    assert "TOOL-004" in rule_ids  # DELETE FROM SQL mutation
    assert report.risk_score >= 60
    assert report.security_grade in ("D", "F")

    # Verify auto-generated starter policy is a valid fail-closed Policy
    policy_doc = generate_starter_policy(report, subject="scanned-agent")
    policy = load_policy(policy_doc)
    assert policy.subject == "scanned-agent"
    # High/critical tools must be halted or denied by default
    eval_shell = policy.evaluate("mcp.shell-runner")
    assert not eval_shell.permitted
    eval_db = policy.evaluate("nuke.production_db")
    assert eval_db.decision is Decision.HALT


def test_cli_scan_and_init_policy(tmp_path: Path) -> None:
    (tmp_path / "claude_desktop_config.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bash-exec": {"command": "bash", "args": ["-c", "echo hi"]}
                }
            }
        ),
        encoding="utf-8",
    )
    out_policy = tmp_path / "generated-policy.yaml"
    runner = CliRunner()
    res = runner.invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--init-policy",
            str(out_policy),
            "--fail-on",
            "CRITICAL",
        ],
    )
    assert res.exit_code == 1
    assert out_policy.exists()
    loaded = load_policy(out_policy)
    assert not loaded.evaluate("mcp.bash-exec").permitted


# ----------------------------------------------------------------------
# 2. RuntimeGate (@gate.guard Decorator & Pre-Execution Receipt)
# ----------------------------------------------------------------------
def test_runtime_gate_sync_and_async_pre_execution_enforcement(tmp_path: Path) -> None:
    policy_doc = {
        "version": 1,
        "subject": "runtime-test-agent",
        "capabilities": [
            {"name": "kb.read", "description": "Read KB"},
            {"name": "payment.refund", "description": "Issue refund"},
        ],
        "rules": [
            {
                "id": "allow-kb",
                "action": "kb.read",
                "effect": "allow",
                "reason": "KB read allowed",
            },
            {
                "id": "allow-scoped-refund",
                "action": "payment.refund",
                "effect": "allow",
                "reason": "Refund requires finance:approve scope",
                "conditions": {"required_scopes": ["finance:approve"]},
            },
            {
                "id": "deny-all",
                "action": "*",
                "effect": "deny",
                "reason": "Default deny",
            },
        ],
    }
    chain_file = tmp_path / "runtime-chain.json"
    storage = CloudStorage(":memory:")
    _, api_key = storage.create_tenant("Test Corp", "sec@test.io", plan="PRO")
    notary = CloudNotary(storage)

    gate = RuntimeGate(
        policy_doc,
        chain_path=chain_file,
        actor="billing-bot",
        default_scopes=["kb:viewer"],
        cloud_notary=notary,
        api_key=api_key,
    )

    executed: list[str] = []

    @gate.guard("kb.read")
    def read_kb(topic: str) -> str:
        executed.append(f"read:{topic}")
        return f"article:{topic}"

    @gate.guard("payment.refund")
    def refund_Order(order_id: str, amount: int) -> dict:
        executed.append(f"refund:{order_id}")
        return {"refunded": amount}

    @gate.guard("kb.read")
    async def async_read_kb(topic: str) -> str:
        executed.append(f"async_read:{topic}")
        return f"async:{topic}"

    # 1. Permitted call executes and emits receipt #1
    assert read_kb("pricing") == "article:pricing"
    assert executed == ["read:pricing"]
    assert len(gate.chain.receipts) == 1
    assert gate.chain.receipts[0].decision is Decision.ALLOW

    # 2. Disallowed call raises PolicyDeniedError BEFORE side effect runs,
    #    yet still records signed DENY receipt #2!
    with pytest.raises(PolicyDeniedError) as exc_info:
        refund_Order("ord_123", 500)
    assert "refund:ord_123" not in executed
    assert exc_info.value.receipt.seq == 1
    assert exc_info.value.receipt.decision is Decision.DENY
    assert len(gate.chain.receipts) == 2

    # 3. wrap_tools dictionary helper works and records receipt #3
    wrapped = gate.wrap_tools({"kb.read": lambda topic: f"wrapped:{topic}"})
    out = wrapped["kb.read"](topic="faq")
    assert out == "wrapped:faq"
    assert len(gate.chain.receipts) == 3

    # 4. Every receipt was counter-signed by Cloud Witness
    assert len(gate.notarized_receipts) == 3
    for nr in gate.notarized_receipts:
        assert verify_witness_signature(nr, notary.witness_pubkey_hex)


# ----------------------------------------------------------------------
# 3. Lloyd's AIUC-1 Insurability Scorecard & Framework Mappings
# ----------------------------------------------------------------------
def test_insurability_scorecard_tiers_and_cli(tmp_path: Path) -> None:
    assert "aiuc-1-insurability" in FRAMEWORK_MAPPINGS
    assert "eu-cra-art14" in FRAMEWORK_MAPPINGS
    assert "soc2-cc6-cc7" in FRAMEWORK_MAPPINGS

    policy_doc = {
        "version": 1,
        "subject": "underwriting-bot",
        "capabilities": ["doc.read"],
        "rules": [
            {"id": "r1", "action": "doc.read", "effect": "allow", "reason": "Safe read"},
            {"id": "r2", "action": "*", "effect": "deny", "reason": "Default deny"},
        ],
    }
    chain_path = tmp_path / "chain.json"
    gate = RuntimeGate(policy_doc, chain_path=chain_path)
    gate.evaluate_and_record("doc.read", inputs={"id": 1})
    gate.evaluate_and_record("shell.exec", inputs={"cmd": "whoami"})

    # Unsealed & un-notarized -> TIER_2_STANDARD (75 pts)
    card_unsealed = compute_insurability_score(gate.chain, notarized_count=0)
    assert card_unsealed.insurability_score == 75
    assert card_unsealed.underwriting_tier == "TIER_2_STANDARD"

    # Fully cloud-notarized -> TIER_1_PREFERRED (100 pts)
    card_notarized = compute_insurability_score(gate.chain, notarized_count=2)
    assert card_notarized.insurability_score == 100
    assert card_notarized.underwriting_tier == "TIER_1_PREFERRED"

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["insurability", str(chain_path), "--notarized-count", "2", "--json"],
    )
    assert res.exit_code == 0
    parsed = json.loads(res.output)
    assert parsed["underwriting_tier"] == "TIER_1_PREFERRED"


# ----------------------------------------------------------------------
# 4. Multi-Tenant Cloud Witness, Quota Enforcement (HTTP 402), & Server API
# ----------------------------------------------------------------------
def test_cloud_notary_rejects_forged_receipt_and_enforces_quota() -> None:
    storage = CloudStorage(":memory:")
    tenant, api_key = storage.create_tenant(
        "Tiny Startup", "founder@tiny.ai", plan=SubscriptionPlan.FREE, custom_quota=1
    )
    notary = CloudNotary(storage)

    policy_doc = {
        "version": 1,
        "subject": "tiny-agent",
        "capabilities": ["ping"],
        "rules": [{"id": "allow-ping", "action": "ping", "effect": "allow", "reason": "ok"}],
    }
    gate = RuntimeGate(policy_doc)
    _, r1 = gate.evaluate_and_record("ping")
    _, r2 = gate.evaluate_and_record("ping")

    # 1st receipt succeeds within quota=1
    res1 = notary.notarize_receipt(
        api_key=api_key,
        chain_id=gate.chain.chain_id,
        subject=gate.chain.subject,
        public_key_hex=gate.chain.public_key_hex,
        receipt_dict=r1.to_dict(),
    )
    assert res1["status"] == "NOTARIZED"
    assert verify_witness_signature(res1, notary.witness_pubkey_hex)

    # 2nd receipt exceeds quota=1 -> raises QuotaExceededError
    with pytest.raises(QuotaExceededError):
        notary.notarize_receipt(
            api_key=api_key,
            chain_id=gate.chain.chain_id,
            subject=gate.chain.subject,
            public_key_hex=gate.chain.public_key_hex,
            receipt_dict=r2.to_dict(),
        )

    # Upgrade to PRO ($99/mo, 100,000 quota) -> 2nd receipt now succeeds!
    upgrade = storage.upgrade_plan(tenant.tenant_id, SubscriptionPlan.PRO)
    assert upgrade["charged_usd"] == 99
    res2 = notary.notarize_receipt(
        api_key=api_key,
        chain_id=gate.chain.chain_id,
        subject=gate.chain.subject,
        public_key_hex=gate.chain.public_key_hex,
        receipt_dict=r2.to_dict(),
    )
    assert res2["seq"] == 1

    # Forged / tampered receipt is rejected with NotarizationError
    forged = r2.to_dict()
    forged["decision"] = "DENY"
    with pytest.raises(NotarizationError):
        notary.notarize_receipt(
            api_key=api_key,
            chain_id=gate.chain.chain_id,
            subject=gate.chain.subject,
            public_key_hex=gate.chain.public_key_hex,
            receipt_dict=forged,
        )


def test_cloud_console_and_seeded_environment_end_to_end() -> None:
    from agentproof.cloud.server import seed_demo_environment
    from agentproof.cloud.ui import render_cloud_console_html

    storage = CloudStorage(":memory:")
    notary = CloudNotary(storage)
    demo_tenant_id, demo_api_key = seed_demo_environment(notary)

    metrics = storage.platform_metrics()
    assert metrics["arr_usd"] == (99 + 1500) * 12  # Seeded PRO + ENTERPRISE
    assert metrics["paid_tenants"] == 2

    html = render_cloud_console_html(
        witness_pubkey=notary.witness_pubkey_hex,
        demo_api_key=demo_api_key,
        demo_tenant_id=demo_tenant_id,
    )
    assert "AgentProof Cloud" in html
    assert demo_tenant_id in html

    receipts = storage.list_notarized_receipts(demo_tenant_id)
    assert len(receipts) == 4
    decisions = [r["decision"] for r in receipts]
    assert "ALLOW" in decisions
    assert "HALT" in decisions
    assert "DENY" in decisions


# ----------------------------------------------------------------------
# 5. Strategic Acquirer Exporters (Vanta / Drata / Datadog) & Billing Webhooks
# ----------------------------------------------------------------------
def test_strategic_acquirer_exporters_vanta_drata_datadog(tmp_path: Path) -> None:
    policy_doc = {
        "version": 1,
        "subject": "acquirer-demo-agent",
        "capabilities": ["kb.read"],
        "rules": [
            {"id": "r1", "action": "kb.read", "effect": "allow", "reason": "ok"},
            {"id": "r2", "action": "*", "effect": "deny", "reason": "deny"},
        ],
    }
    chain_path = tmp_path / "export-chain.json"
    gate = RuntimeGate(policy_doc, chain_path=chain_path)
    gate.evaluate_and_record("kb.read", inputs={"q": "soc2"})
    gate.evaluate_and_record("shell.exec", inputs={"cmd": "id"})

    runner = CliRunner()
    for target in ("vanta", "drata", "datadog"):
        out_file = tmp_path / f"{target}.json"
        res = runner.invoke(
            main,
            [
                "export",
                str(chain_path),
                "--target",
                target,
                "--notarized-count",
                "2",
                "--out",
                str(out_file),
            ],
        )
        assert res.exit_code == 0
        payload = json.loads(out_file.read_text(encoding="utf-8"))
        if target == "vanta":
            assert payload["schema_version"] == "vanta.custom_evidence.v1"
            assert payload["status"] == "PASS"
            assert payload["insurability_scorecard"]["insurability_score"] == 100
        elif target == "drata":
            assert payload["schema"] == "drata.autopilot.evidence.v1"
            assert payload["compliant"] is True
        elif target == "datadog":
            assert payload["schema"] == "datadog.logs.intake.v2"
            assert len(payload["events"]) == 2


def test_stripe_and_lemonsqueezy_hmac_billing_webhooks() -> None:
    import hashlib
    import hmac

    from agentproof.cloud import (
        WebhookVerificationError,
        process_billing_webhook,
    )

    storage = CloudStorage(":memory:")
    tenant, _ = storage.create_tenant("Acme SaaS", "billing@acme.io", plan="FREE")
    secret = "whsec_live_super_secret_key_999"

    # 1. LemonSqueezy style webhook (X-Signature hex HMAC)
    ls_body = json.dumps(
        {
            "meta": {
                "event_name": "subscription_created",
                "custom_data": {"tenant_id": tenant.tenant_id, "plan": "PRO"},
            },
            "data": {"id": "ls_sub_8821"},
        }
    ).encode("utf-8")
    ls_sig = hmac.new(secret.encode("utf-8"), ls_body, hashlib.sha256).hexdigest()

    res_ls = process_billing_webhook(
        storage,
        raw_body=ls_body,
        signature_header=ls_sig,
        webhook_secret=secret,
    )
    assert res_ls["tenant"]["plan"] == "PRO"
    assert res_ls["charged_usd"] == 99

    # 2. Stripe style webhook (`t=...,v1=...`) upgrading to ENTERPRISE ($1,500/mo)
    stripe_body = json.dumps(
        {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_live_99123",
                    "client_reference_id": tenant.tenant_id,
                    "metadata": {"plan": "ENTERPRISE"},
                }
            },
        }
    ).encode("utf-8")
    ts = "1762800000"
    stripe_v1 = hmac.new(
        secret.encode("utf-8"),
        f"{ts}.".encode("utf-8") + stripe_body,
        hashlib.sha256,
    ).hexdigest()
    stripe_header = f"t={ts},v1={stripe_v1}"

    res_stripe = process_billing_webhook(
        storage,
        raw_body=stripe_body,
        signature_header=stripe_header,
        webhook_secret=secret,
    )
    assert res_stripe["tenant"]["plan"] == "ENTERPRISE"
    assert res_stripe["charged_usd"] == 1500

    # 3. Forged signature must raise WebhookVerificationError
    with pytest.raises(WebhookVerificationError):
        process_billing_webhook(
            storage,
            raw_body=stripe_body,
            signature_header="t=1762800000,v1=deadbeef",
            webhook_secret=secret,
        )


# ----------------------------------------------------------------------
# 6. Automated Growth Scout (`agentproof scout`) & Cloud CORS/Export API
# ----------------------------------------------------------------------
def test_growth_scout_generates_ranked_pipeline_and_outreach(tmp_path: Path) -> None:
    repos_dir = tmp_path / "repos"
    risky_repo = repos_dir / "acme-ai-agent"
    safe_repo = repos_dir / "clean-repo"
    risky_repo.mkdir(parents=True)
    safe_repo.mkdir(parents=True)

    (risky_repo / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "shell-runner": {
                        "command": "npx",
                        "args": ["-y", "mcp-server-shell", "/"],
                        "env": {"OPENAI_API_KEY": "sk-live-secret-123456"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (safe_repo / "README.md").write_text("# safe repo", encoding="utf-8")

    leads_dir = tmp_path / "leads"
    runner = CliRunner()
    res = runner.invoke(
        main,
        ["scout", "--dir", str(repos_dir), "--out-dir", str(leads_dir), "--json"],
    )
    assert res.exit_code == 0
    summary = json.loads(res.output)
    assert summary["scanned_count"] == 2
    assert summary["qualified_count"] == 1
    assert summary["leads"][0]["repo_name"] == "acme-ai-agent"

    lead_folder = leads_dir / "acme-ai-agent"
    assert (lead_folder / "policy.yaml").exists()
    assert (lead_folder / "audit-report.md").exists()
    assert (lead_folder / "outreach.md").exists()
    assert (leads_dir / "pipeline.csv").exists()
    assert (leads_dir / "pipeline.json").exists()
    loaded_policy = load_policy(lead_folder / "policy.yaml")
    assert not loaded_policy.evaluate("mcp.shell-runner").permitted


def test_bilingual_site_and_cloud_export_payload() -> None:
    site_html = (Path(__file__).resolve().parent.parent / "site" / "index.html").read_text(
        encoding="utf-8"
    )
    # The live site is self-contained (no external CDN) and sells the audit service.
    assert "cdn.tailwindcss.com" not in site_html
    assert "assets/scanner.js" in site_html
    assert "audit-service" in site_html
    assert "Quick Audit" in site_html
    # The v0.2.0 single-file site is archived under docs/v0.2.0 for reference.
    archived = (
        Path(__file__).resolve().parent.parent / "docs" / "v0.2.0" / "site" / "index.html"
    ).read_text(encoding="utf-8")
    assert "cdn.tailwindcss.com" in archived
    assert "/api/v1/tenants" in archived

    from agentproof.cloud.server import seed_demo_environment
    from agentproof.core.receipt import Receipt
    from agentproof.core.verify import load_public_key_hex, verify_receipts
    from agentproof.core.chain import Chain
    from agentproof.exporters import build_target_export

    storage = CloudStorage(":memory:")
    notary = CloudNotary(storage)
    tenant_id, _ = seed_demo_environment(notary)
    rows = storage.list_notarized_receipts(tenant_id, limit=50)
    chain_id = rows[0]["chain_id"]
    ordered_rows = storage.list_notarized_receipts(tenant_id, chain_id=chain_id, limit=50)
    receipts = sorted(
        [Receipt.from_dict(r["receipt"]) for r in ordered_rows],
        key=lambda r: r.seq,
    )
    pub = load_public_key_hex(ordered_rows[0]["client_pubkey"])
    chain = Chain.from_records(receipts, pub, chain_id=chain_id, subject="acme")
    v = verify_receipts(receipts, pub)
    vanta = build_target_export("vanta", chain, verification=v, notarized_count=len(receipts))
    assert vanta["status"] == "PASS"
    assert vanta["insurability_scorecard"]["insurability_score"] == 100

"""API contract tests: scans, signup, dual-signed ledger, tamper detection, exports."""

from __future__ import annotations

import sqlite3

import pytest

from server import app as app_module
from server import config


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["service"] == "agentproof-cloud"
    assert body["mode"] == "sandbox-checkout"
    assert isinstance(body["arr"], int)


def test_plans_catalogue(client):
    body = client.get("/api/plans").json()
    assert set(body["plans"][0]) >= {"id", "name", "price_monthly", "quota_events", "features"}
    assert {plan["id"] for plan in body["plans"]} == {"free", "pro", "enterprise"}
    assert set(body["vendors"]) == {"vanta", "drata", "datadog", "aiuc1"}


def test_scan_endpoint_and_stats(client, sample_texts):
    before = client.get("/api/stats").json()["scans_total"]
    response = client.post("/api/scan", json={"kind": "mcp", "content": sample_texts["danger_mcp"]})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"].startswith("scan_")
    assert body["result"]["grade"] == "F"
    assert body["result"]["findings"]
    after = client.get("/api/stats").json()["scans_total"]
    assert after == before + 1


def test_scan_rejects_bad_input(client):
    response = client.post("/api/scan", json={"kind": "mcp", "content": "{oops"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "scan_input_error"


def test_signup_validation(client):
    assert client.post("/api/signup", json={"company": "A", "email": "a@b.co", "plan": "pro"}).status_code == 422
    assert client.post("/api/signup", json={"company": "Acme", "email": "not-an-email", "plan": "pro"}).status_code == 422
    assert client.post("/api/signup", json={"company": "Acme", "email": "a@b.co", "plan": "ultra"}).status_code == 422


def test_signup_issues_tenant_and_key(fresh_tenant):
    payload = fresh_tenant(plan="pro")
    assert payload["api_key"].startswith("ap_live_")
    assert len(payload["api_key"]) == len("ap_live_") + 32
    tenant = payload["tenant"]
    assert tenant["id"].startswith("t_")
    assert tenant["plan"] == "pro"
    assert payload["plan"]["quota_events"] == 5000
    assert payload["checkout"]["mode"] == "sandbox"
    assert payload["checkout"]["charged"] is False
    assert payload["arr"]["arr"] >= 1188


def test_free_signup_uses_free_key_prefix(fresh_tenant):
    payload = fresh_tenant(plan="free")
    assert payload["api_key"].startswith("ap_free_")
    assert payload["arr"]["arr"] >= 0


def test_auth_required_and_invalid(client):
    assert client.get("/api/me").status_code == 401
    response = client.get("/api/me", headers={"X-API-Key": "ap_live_" + "0" * 32})
    assert response.status_code == 401
    assert response.json()["error"]["code"] in {"invalid_api_key", "missing_api_key"}


def test_me_and_login(fresh_tenant, client):
    payload = fresh_tenant()
    headers = {"X-API-Key": payload["api_key"]}
    me = client.get("/api/me", headers=headers).json()
    assert me["tenant"]["id"] == payload["tenant"]["id"]
    assert me["usage"]["quota_events"] == 5000
    assert len(me["fingerprints"]["platform"]) == 64
    assert len(me["fingerprints"]["tenant"]) == 64

    login = client.post("/api/login", json={"api_key": payload["api_key"]})
    assert login.status_code == 200
    assert login.json()["tenant"]["id"] == payload["tenant"]["id"]


def test_ledger_simulation_appends_and_verifies(fresh_tenant, client):
    payload = fresh_tenant()
    headers = {"X-API-Key": payload["api_key"]}

    response = client.post(
        "/api/ledger/simulate",
        headers=headers,
        json={"action": "order.refund", "decision": "DENY", "reason": "over limit"},
    )
    assert response.status_code == 200
    record = response.json()["record"]
    assert record["seq"] == 2  # 1 = tenant.created
    assert record["decision"] == "DENY"
    assert len(record["platform_sig"]) == 128
    assert len(record["tenant_sig"]) == 128
    assert record["prev_hash"] != "0" * 64

    ledger = client.get("/api/ledger", headers=headers).json()
    assert ledger["events"][0]["seq"] == 2  # newest first
    assert ledger["events"][1]["action"] == "tenant.created"

    verification = client.get("/api/verify", headers=headers).json()
    assert verification["result"] == "PASS"
    assert verification["records"] == 2
    assert verification["seal"]["present"] is True
    assert verification["seal"]["matches"] is True
    assert all(check["ok"] for check in verification["checks"])


def test_tampered_ledger_fails_verification(fresh_tenant, client, db_path):
    payload = fresh_tenant()
    tenant_id = payload["tenant"]["id"]
    headers = {"X-API-Key": payload["api_key"]}
    client.post("/api/ledger/simulate", headers=headers, json={"action": "kb.search", "decision": "ALLOW"})

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE ledger SET decision = 'ALLOW', reason = 'tampered' WHERE tenant_id = ? AND seq = 2",
            (tenant_id,),
        )
        conn.commit()
    finally:
        conn.close()

    verification = client.get("/api/verify", headers=headers).json()
    assert verification["result"] == "FAIL"
    assert any("第 2 条" in check["detail"] for check in verification["checks"] if not check["ok"])


def test_deleted_record_fails_verification(fresh_tenant, client, db_path):
    payload = fresh_tenant()
    tenant_id = payload["tenant"]["id"]
    headers = {"X-API-Key": payload["api_key"]}
    client.post("/api/ledger/simulate", headers=headers, json={"action": "kb.search", "decision": "ALLOW"})
    client.post("/api/ledger/simulate", headers=headers, json={"action": "db.write", "decision": "DENY"})

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM ledger WHERE tenant_id = ? AND seq = 2", (tenant_id,))
        conn.commit()
    finally:
        conn.close()

    verification = client.get("/api/verify", headers=headers).json()
    assert verification["result"] == "FAIL"


@pytest.mark.parametrize(
    "vendor,expected_format",
    [
        ("vanta", "vanta.evidence_pack"),
        ("drata", "drata.monitoring_results"),
        ("datadog", "datadog.events.v1"),
        ("aiuc1", "lloyds.aiuc1.underwriting_pack"),
    ],
)
def test_exports(fresh_tenant, client, vendor, expected_format):
    payload = fresh_tenant()
    response = client.get(f"/api/export/{vendor}", headers={"X-API-Key": payload["api_key"]})
    assert response.status_code == 200
    body = response.json()
    assert body["format"] == expected_format
    assert body["mapping_status"] == "draft"
    assert body["integrity"]["result"] == "PASS"
    assert "disclaimer" in body


def test_unknown_vendor_404(fresh_tenant, client):
    payload = fresh_tenant()
    response = client.get("/api/export/acme", headers={"X-API-Key": payload["api_key"]})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_vendor"


def test_quota_enforced(fresh_tenant, client, monkeypatch):
    monkeypatch.setitem(config.PLANS["free"], "quota_events", 2)
    payload = fresh_tenant(plan="free")
    headers = {"X-API-Key": payload["api_key"]}

    first = client.post("/api/ledger/simulate", headers=headers, json={"action": "kb.search", "decision": "ALLOW"})
    assert first.status_code == 200
    second = client.post("/api/ledger/simulate", headers=headers, json={"action": "kb.search", "decision": "ALLOW"})
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "quota_exceeded"


def test_scan_rate_limit(client, sample_texts, monkeypatch):
    monkeypatch.setattr(app_module, "_RATE", {})
    monkeypatch.setattr(app_module, "SCAN_RATE_LIMIT", 2)
    for _ in range(2):
        assert client.post("/api/scan", json={"kind": "mcp", "content": sample_texts["safe_mcp"]}).status_code == 200
    blocked = client.post("/api/scan", json={"kind": "mcp", "content": sample_texts["safe_mcp"]})
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"


def test_unknown_account_key_does_not_leak_tenant(client):
    response = client.post("/api/login", json={"api_key": "ap_live_" + "f" * 32})
    assert response.status_code == 401
    assert "message" in response.json()["error"]

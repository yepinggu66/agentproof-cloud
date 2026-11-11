"""Tenant lifecycle, quotas, billing roll-up and scan counters."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet

from . import config, ledger, signing

__all__ = [
    "QuotaExceeded",
    "create_tenant",
    "find_tenant_by_api_key",
    "get_tenant",
    "usage_for",
    "arr_summary",
    "record_scan",
    "platform_stats",
    "hash_api_key",
]


class QuotaExceeded(RuntimeError):
    def __init__(self, used: int, quota: int, plan: str) -> None:
        super().__init__(f"本月已用 {used}/{quota} 条签名决策（{plan} 套餐）")
        self.used = used
        self.quota = quota
        self.plan = plan


def hash_api_key(api_key: str) -> str:
    return signing.sha256_hex(api_key)


def _month_start_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")


def create_tenant(
    conn: sqlite3.Connection,
    *,
    master: Fernet,
    platform_private_pem: bytes,
    company: str,
    email: str,
    plan_id: str,
    billing: str,
) -> tuple[dict[str, Any], str]:
    plan = config.plan_or_raise(plan_id)
    prefix = "ap_live" if plan["price_monthly"] > 0 else "ap_free"
    api_key = f"{prefix}_{secrets.token_hex(16)}"
    tenant_private_pem, tenant_public_pem = signing.generate_keypair_pem()
    tenant_id = "t_" + secrets.token_hex(6)
    created_at = ledger.now_iso()

    tenant = {
        "id": tenant_id,
        "company": company.strip(),
        "email": email.strip().lower(),
        "plan": plan["id"],
        "billing": "annual" if (billing or "monthly").lower() == "annual" else "monthly",
        "api_key_sha256": hash_api_key(api_key),
        "api_key_prefix": api_key[:14] + "\u2026",
        "tenant_public_pem": tenant_public_pem.decode("utf-8"),
        "tenant_private_enc": signing.encrypt_private_key(master, tenant_private_pem),
        "created_at": created_at,
        "status": "active",
    }
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            INSERT INTO tenants (
                id, company, email, plan, billing, api_key_sha256, api_key_prefix,
                tenant_public_pem, tenant_private_enc, created_at, status
            ) VALUES (
                :id, :company, :email, :plan, :billing, :api_key_sha256, :api_key_prefix,
                :tenant_public_pem, :tenant_private_enc, :created_at, :status
            )
            """,
            tenant,
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    ledger.append_event(
        conn,
        tenant=tenant,
        master=master,
        platform_private_pem=platform_private_pem,
        actor=f"billing:{plan['id']}",
        action="tenant.created",
        decision="ALLOW",
        reason=f"{company} 开通 {plan['name']}（{tenant['billing']}）",
        policy_id="agentproof-onboarding-v1",
        inputs={"email": tenant["email"], "plan": plan["id"], "billing": tenant["billing"]},
        source="signup",
    )
    return tenant, api_key


def find_tenant_by_api_key(conn: sqlite3.Connection, api_key: str) -> dict[str, Any] | None:
    if not api_key or len(api_key) < 16:
        return None
    row = conn.execute(
        "SELECT * FROM tenants WHERE api_key_sha256 = ? AND status = 'active'",
        (hash_api_key(api_key),),
    ).fetchone()
    return dict(row) if row is not None else None


def get_tenant(conn: sqlite3.Connection, tenant_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
    return dict(row) if row is not None else None


def usage_for(conn: sqlite3.Connection, tenant: dict[str, Any]) -> dict[str, Any]:
    plan = config.plan_or_raise(tenant["plan"])
    month_start = _month_start_iso()
    used = conn.execute(
        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id = ? AND ts >= ?",
        (tenant["id"], month_start),
    ).fetchone()["n"]
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM ledger WHERE tenant_id = ?", (tenant["id"],)
    ).fetchone()["n"]
    return {
        "plan": plan["id"],
        "plan_name": plan["name"],
        "quota_events": plan["quota_events"],
        "used_this_month": int(used),
        "remaining": max(plan["quota_events"] - int(used), 0),
        "records_total": int(total),
        "retention_days": plan["retention_days"],
        "seats": plan["seats"],
        "period_start": month_start,
        "price_monthly": plan["price_monthly"],
        "price_annual": plan["price_annual"],
        "billing": tenant["billing"],
    }


def arr_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute("SELECT plan, billing FROM tenants WHERE status = 'active'").fetchall()
    arr = 0
    by_plan: dict[str, dict[str, int]] = {}
    for row in rows:
        try:
            annual = config.arr_for(row["plan"], row["billing"])
        except ValueError:
            continue
        arr += annual
        bucket = by_plan.setdefault(row["plan"], {"tenants": 0, "arr": 0})
        bucket["tenants"] += 1
        bucket["arr"] += annual
    return {
        "arr": arr,
        "mrr": round(arr / 12),
        "active_tenants": len(rows),
        "by_plan": by_plan,
        "currency": "USD",
    }


def record_scan(conn: sqlite3.Connection, result: dict[str, Any], subject: str) -> str:
    scan_id = "scan_" + secrets.token_hex(6)
    conn.execute(
        "INSERT INTO scans (id, ts, kind, grade, score, findings, subject) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            result.get("scanned_at") or ledger.now_iso(),
            result["kind"],
            result["grade"],
            int(result["score"]),
            len(result["findings"]),
            subject[:80],
        ),
    )
    return scan_id


def platform_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
    decisions = conn.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"]
    tenants = conn.execute("SELECT COUNT(*) AS n FROM tenants WHERE status = 'active'").fetchone()["n"]
    day_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today = conn.execute(
        "SELECT COUNT(*) AS n FROM ledger WHERE ts >= ?",
        (day_start.isoformat().replace("+00:00", "Z"),),
    ).fetchone()["n"]
    return {
        "scans_total": int(scans),
        "decisions_total": int(decisions),
        "decisions_today": int(today),
        "tenants_active": int(tenants),
        **arr_summary(conn),
    }

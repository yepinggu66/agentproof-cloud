"""Multi-tenant SQLite/Postgres-compatible ledger for AgentProof Cloud SaaS."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class SubscriptionPlan(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


PLAN_SPECS: dict[SubscriptionPlan, dict[str, Any]] = {
    SubscriptionPlan.FREE: {
        "name": "Free OSS Developer",
        "price_monthly_usd": 0,
        "monthly_quota": 1_000,
        "features": [
            "1,000 Cloud Witness notarized receipts / mo",
            "Local CLI & Shadow MCP Scanner",
            "EU AI Act Art. 26 basic Markdown export",
        ],
    },
    SubscriptionPlan.PRO: {
        "name": "Pro Compliance Team",
        "price_monthly_usd": 99,
        "monthly_quota": 100_000,
        "features": [
            "100,000 Cloud Witness counter-signed receipts / mo",
            "Out-of-Band Ed25519 Witness Notary (anti-rewrite guarantee)",
            "CI/CD Regression Gate & Webhook alerts",
            "SOC 2 CC6/CC7 & ISO 42001 Evidence Pack",
        ],
    },
    SubscriptionPlan.ENTERPRISE: {
        "name": "Enterprise & AIUC-1 Insurability",
        "price_monthly_usd": 1500,
        "monthly_quota": 10_000_000,
        "features": [
            "10,000,000 WORM-locked notarized receipts / mo",
            "Lloyd's AIUC-1 Insurability Scorecard & Underwriting Pack",
            "Dedicated Auditor Read-Only Verification Portal",
            "Custom SLA & EU CRA Art. 14 24h incident bundle",
        ],
    },
}


def _utc_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@dataclass
class TenantRecord:
    tenant_id: str
    org_name: str
    email: str
    plan: SubscriptionPlan
    monthly_quota: int
    receipts_used: int
    stripe_customer_id: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        spec = PLAN_SPECS[self.plan]
        return {
            "tenant_id": self.tenant_id,
            "org_name": self.org_name,
            "email": self.email,
            "plan": self.plan.value,
            "plan_name": spec["name"],
            "price_monthly_usd": spec["price_monthly_usd"],
            "monthly_quota": self.monthly_quota,
            "receipts_used": self.receipts_used,
            "quota_remaining": max(0, self.monthly_quota - self.receipts_used),
            "stripe_customer_id": self.stripe_customer_id,
            "created_at": self.created_at,
        }


class CloudStorage:
    """ACID multi-tenant storage backing AgentProof Cloud."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    org_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    plan TEXT NOT NULL DEFAULT 'FREE',
                    monthly_quota INTEGER NOT NULL DEFAULT 1000,
                    receipts_used INTEGER NOT NULL DEFAULT 0,
                    stripe_customer_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                );

                CREATE TABLE IF NOT EXISTS notarized_receipts (
                    notary_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    record_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    notarized_at TEXT NOT NULL,
                    client_pubkey TEXT NOT NULL,
                    witness_pubkey TEXT NOT NULL,
                    witness_signature TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                );

                CREATE TABLE IF NOT EXISTS billing_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    from_plan TEXT NOT NULL,
                    to_plan TEXT NOT NULL,
                    amount_usd INTEGER NOT NULL,
                    payment_ref TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_tenant(
        self,
        org_name: str,
        email: str,
        *,
        plan: SubscriptionPlan | str = SubscriptionPlan.FREE,
        custom_quota: int | None = None,
    ) -> tuple[TenantRecord, str]:
        """Create a tenant and return ``(TenantRecord, raw_api_key)``."""
        plan_enum = SubscriptionPlan(plan) if not isinstance(plan, SubscriptionPlan) else plan
        quota = custom_quota if custom_quota is not None else PLAN_SPECS[plan_enum]["monthly_quota"]
        tenant_id = f"tnt_{uuid.uuid4().hex[:12]}"
        now = _utc_iso()
        stripe_id = f"cus_{uuid.uuid4().hex[:14]}"

        raw_key = f"ap_live_{secrets.token_urlsafe(24)}"
        key_id = f"key_{uuid.uuid4().hex[:10]}"
        key_hash = _hash_api_key(raw_key)

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO tenants (
                    tenant_id, org_name, email, plan, monthly_quota,
                    receipts_used, stripe_customer_id, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (tenant_id, org_name, email, plan_enum.value, quota, stripe_id, now),
            )
            self._conn.execute(
                """
                INSERT INTO api_keys (
                    key_id, tenant_id, key_prefix, key_hash, label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, tenant_id, raw_key[:14], key_hash, "Default Production Key", now),
            )

        return self.get_tenant(tenant_id), raw_key

    def authenticate_key(self, raw_api_key: str) -> TenantRecord | None:
        if not raw_api_key:
            return None
        key_hash = _hash_api_key(raw_api_key.strip())
        row = self._conn.execute(
            """
            SELECT t.* FROM tenants t
            JOIN api_keys k ON k.tenant_id = t.tenant_id
            WHERE k.key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_tenant(row)

    def get_tenant(self, tenant_id: str) -> TenantRecord:
        row = self._conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if not row:
            raise KeyError(f"Tenant not found: {tenant_id}")
        return self._row_to_tenant(row)

    def list_tenants(self) -> list[TenantRecord]:
        rows = self._conn.execute(
            "SELECT * FROM tenants ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_tenant(r) for r in rows]

    def upgrade_plan(
        self,
        tenant_id: str,
        new_plan: SubscriptionPlan | str,
        *,
        payment_ref: str = "stripe_sim_ch_ok",
    ) -> dict[str, Any]:
        """Upgrade a tenant's subscription tier and record a billing event."""
        tenant = self.get_tenant(tenant_id)
        target_plan = (
            SubscriptionPlan(new_plan)
            if not isinstance(new_plan, SubscriptionPlan)
            else new_plan
        )
        spec = PLAN_SPECS[target_plan]
        new_quota = spec["monthly_quota"]
        amount = spec["price_monthly_usd"]
        event_id = f"inv_{uuid.uuid4().hex[:12]}"
        now = _utc_iso()

        with self._conn:
            self._conn.execute(
                """
                UPDATE tenants
                SET plan = ?, monthly_quota = ?
                WHERE tenant_id = ?
                """,
                (target_plan.value, new_quota, tenant_id),
            )
            self._conn.execute(
                """
                INSERT INTO billing_events (
                    event_id, tenant_id, from_plan, to_plan, amount_usd, payment_ref, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    tenant_id,
                    tenant.plan.value,
                    target_plan.value,
                    amount,
                    payment_ref,
                    now,
                ),
            )

        updated = self.get_tenant(tenant_id)
        return {
            "invoice_id": event_id,
            "tenant": updated.to_dict(),
            "charged_usd": amount,
            "payment_ref": payment_ref,
            "upgraded_at": now,
        }

    def store_notarized_receipt(
        self,
        *,
        notary_id: str,
        tenant_id: str,
        chain_id: str,
        subject: str,
        seq: int,
        record_hash: str,
        actor: str,
        action: str,
        decision: str,
        reason: str,
        issued_at: str,
        notarized_at: str,
        client_pubkey: str,
        witness_pubkey: str,
        witness_signature: str,
        receipt_dict: dict[str, Any],
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO notarized_receipts (
                    notary_id, tenant_id, chain_id, subject, seq, record_hash,
                    actor, action, decision, reason, issued_at, notarized_at,
                    client_pubkey, witness_pubkey, witness_signature, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notary_id,
                    tenant_id,
                    chain_id,
                    subject,
                    seq,
                    record_hash,
                    actor,
                    action,
                    decision,
                    reason,
                    issued_at,
                    notarized_at,
                    client_pubkey,
                    witness_pubkey,
                    witness_signature,
                    json.dumps(receipt_dict, ensure_ascii=False, sort_keys=True),
                ),
            )
            self._conn.execute(
                """
                UPDATE tenants
                SET receipts_used = receipts_used + 1
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            )

    def list_notarized_receipts(
        self, tenant_id: str, *, chain_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if chain_id:
            rows = self._conn.execute(
                """
                SELECT * FROM notarized_receipts
                WHERE tenant_id = ? AND chain_id = ?
                ORDER BY seq ASC, notarized_at ASC
                LIMIT ?
                """,
                (tenant_id, chain_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT * FROM notarized_receipts
                WHERE tenant_id = ?
                ORDER BY notarized_at DESC, seq DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            results.append(
                {
                    "notary_id": r["notary_id"],
                    "tenant_id": r["tenant_id"],
                    "chain_id": r["chain_id"],
                    "subject": r["subject"],
                    "seq": r["seq"],
                    "record_hash": r["record_hash"],
                    "actor": r["actor"],
                    "action": r["action"],
                    "decision": r["decision"],
                    "reason": r["reason"],
                    "issued_at": r["issued_at"],
                    "notarized_at": r["notarized_at"],
                    "client_pubkey": r["client_pubkey"],
                    "witness_pubkey": r["witness_pubkey"],
                    "witness_signature": r["witness_signature"],
                    "receipt": json.loads(r["receipt_json"]),
                }
            )
        return results

    def platform_metrics(self) -> dict[str, Any]:
        """Return aggregate SaaS MRR/ARR and usage metrics for the M&A Data Room."""
        tenants = self.list_tenants()
        mrr = sum(PLAN_SPECS[t.plan]["price_monthly_usd"] for t in tenants)
        total_notarized = sum(t.receipts_used for t in tenants)
        paid_tenants = sum(1 for t in tenants if t.plan is not SubscriptionPlan.FREE)
        return {
            "total_tenants": len(tenants),
            "paid_tenants": paid_tenants,
            "mrr_usd": mrr,
            "arr_usd": mrr * 12,
            "total_notarized_receipts": total_notarized,
            "plans_breakdown": {
                plan.value: sum(1 for t in tenants if t.plan is plan)
                for plan in SubscriptionPlan
            },
        }

    @staticmethod
    def _row_to_tenant(row: sqlite3.Row) -> TenantRecord:
        return TenantRecord(
            tenant_id=row["tenant_id"],
            org_name=row["org_name"],
            email=row["email"],
            plan=SubscriptionPlan(row["plan"]),
            monthly_quota=int(row["monthly_quota"]),
            receipts_used=int(row["receipts_used"]),
            stripe_customer_id=row["stripe_customer_id"],
            created_at=row["created_at"],
        )

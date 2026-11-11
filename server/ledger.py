"""Append-only, dual-signed ledger with an out-of-band seal.

Chain rule
----------
For each record ``r``::

    body(r) = canonical_json({every field except hash, platform_sig, tenant_sig})
    hash(r) = sha256(body(r))

``prev_hash`` of ``r`` must equal the ``hash`` of ``r-1`` (the first record
uses 64 zeroes). Every record is signed over ``body(r)`` with both the
platform key and the tenant key.

Seal rule
---------
The seal commits to the last record only::

    seal_hash = sha256(canonical_json({tenant_id, seq, final_hash, sealed_at}))

It is what makes a full rewrite by the key holder detectable: publish it
elsewhere and any re-signed chain will no longer match.
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet

from . import signing

__all__ = [
    "GENESIS_HASH",
    "Decisions",
    "now_iso",
    "new_record_id",
    "append_event",
    "load_events",
    "verify_tenant_chain",
]

GENESIS_HASH = "0" * 64
ZERO_HASH = GENESIS_HASH

Decisions = ("ALLOW", "HALT", "DENY")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_record_id() -> str:
    return "rec_" + secrets.token_hex(8)


def _body(record: dict[str, Any]) -> bytes:
    return signing.canonical_bytes(
        {
            "tenant_id": record["tenant_id"],
            "seq": record["seq"],
            "id": record["id"],
            "ts": record["ts"],
            "actor": record["actor"],
            "action": record["action"],
            "decision": record["decision"],
            "reason": record["reason"],
            "policy_id": record["policy_id"],
            "inputs_digest": record["inputs_digest"],
            "prev_hash": record["prev_hash"],
            "source": record["source"],
        }
    )


def append_event(
    conn: sqlite3.Connection,
    *,
    tenant: dict[str, Any],
    master: Fernet,
    platform_private_pem: bytes,
    actor: str,
    action: str,
    decision: str,
    reason: str,
    policy_id: str = "agentproof-default",
    inputs: dict[str, Any] | str | None = None,
    source: str = "api",
) -> dict[str, Any]:
    """Append one signed decision to the tenant's ledger. Caller holds the lock."""
    if decision not in Decisions:
        raise ValueError(f"decision must be one of {Decisions}")

    last = conn.execute(
        "SELECT seq, hash FROM ledger WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1",
        (tenant["id"],),
    ).fetchone()
    seq = 1 if last is None else int(last["seq"]) + 1
    prev_hash = GENESIS_HASH if last is None else str(last["hash"])

    record = {
        "tenant_id": tenant["id"],
        "seq": seq,
        "id": new_record_id(),
        "ts": now_iso(),
        "actor": actor[:80] or "unknown",
        "action": action[:120] or "unknown",
        "decision": decision,
        "reason": reason[:400],
        "policy_id": (policy_id or "agentproof-default")[:80],
        "inputs_digest": signing.sha256_hex(inputs if inputs is not None else {}),
        "prev_hash": prev_hash,
        "source": source[:32],
    }
    body = _body(record)
    record["hash"] = signing.sha256_hex(body)

    tenant_private_pem = signing.decrypt_private_key(master, tenant["tenant_private_enc"])
    record["platform_sig"] = signing.sign_hex(platform_private_pem, body)
    record["tenant_sig"] = signing.sign_hex(tenant_private_pem, body)

    conn.execute(
        """
        INSERT INTO ledger (
            tenant_id, seq, id, ts, actor, action, decision, reason, policy_id,
            inputs_digest, prev_hash, hash, platform_sig, tenant_sig, source
        ) VALUES (
            :tenant_id, :seq, :id, :ts, :actor, :action, :decision, :reason, :policy_id,
            :inputs_digest, :prev_hash, :hash, :platform_sig, :tenant_sig, :source
        )
        """,
        record,
    )
    _upsert_seal(conn, tenant["id"], seq, record["hash"], platform_private_pem)
    return record


def _seal_bytes(tenant_id: str, seq: int, final_hash: str, sealed_at: str) -> bytes:
    return signing.canonical_bytes(
        {"tenant_id": tenant_id, "seq": seq, "final_hash": final_hash, "sealed_at": sealed_at}
    )


def _upsert_seal(
    conn: sqlite3.Connection,
    tenant_id: str,
    seq: int,
    final_hash: str,
    platform_private_pem: bytes,
) -> dict[str, Any]:
    sealed_at = now_iso()
    seal_body = _seal_bytes(tenant_id, seq, final_hash, sealed_at)
    seal = {
        "tenant_id": tenant_id,
        "seq": seq,
        "final_hash": final_hash,
        "seal_hash": signing.sha256_hex(seal_body),
        "platform_sig": signing.sign_hex(platform_private_pem, seal_body),
        "sealed_at": sealed_at,
    }
    conn.execute(
        """
        INSERT INTO seals (tenant_id, seq, final_hash, seal_hash, platform_sig, sealed_at)
        VALUES (:tenant_id, :seq, :final_hash, :seal_hash, :platform_sig, :sealed_at)
        ON CONFLICT(tenant_id) DO UPDATE SET
            seq = excluded.seq,
            final_hash = excluded.final_hash,
            seal_hash = excluded.seal_hash,
            platform_sig = excluded.platform_sig,
            sealed_at = excluded.sealed_at
        """,
        seal,
    )
    return seal


def load_events(conn: sqlite3.Connection, tenant_id: str, *, limit: int | None = None) -> list[dict[str, Any]]:
    if limit is None:
        rows = conn.execute(
            "SELECT * FROM ledger WHERE tenant_id = ? ORDER BY seq ASC",
            (tenant_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM (SELECT * FROM ledger WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?) ORDER BY seq ASC",
            (tenant_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def verify_tenant_chain(
    conn: sqlite3.Connection,
    *,
    tenant: dict[str, Any],
    platform_public_pem: bytes,
) -> dict[str, Any]:
    events = load_events(conn, tenant["id"])
    checks: list[dict[str, Any]] = []
    ok = True
    broken_at: int | None = None
    expected_prev = GENESIS_HASH

    for index, event in enumerate(events, start=1):
        body = _body(event)
        expected_hash = signing.sha256_hex(body)
        chain_ok = event["seq"] == index and event["prev_hash"] == expected_prev
        hash_ok = event["hash"] == expected_hash
        platform_ok = signing.verify_hex(platform_public_pem, body, event["platform_sig"])
        tenant_ok = signing.verify_hex(tenant["tenant_public_pem"], body, event["tenant_sig"])
        if not (chain_ok and hash_ok and platform_ok and tenant_ok):
            ok = False
            broken_at = index
            checks.append(
                {
                    "id": f"record-{index}",
                    "ok": False,
                    "detail": _record_failure(chain_ok, hash_ok, platform_ok, tenant_ok, index),
                }
            )
            break
        expected_prev = event["hash"]

    if not events:
        checks.append({"id": "records", "ok": True, "detail": "账本为空：没有可验证的记录"})
    else:
        checks.insert(
            0,
            {
                "id": "hash-chain",
                "ok": ok,
                "detail": (
                    f"{len(events)} 条记录哈希链完整"
                    if ok
                    else f"第 {broken_at} 条记录起校验失败"
                ),
            },
        )
        checks.append({"id": "signatures", "ok": ok, "detail": "平台签名 + 租户签名均校验通过" if ok else "签名校验失败"})

    seal = conn.execute("SELECT * FROM seals WHERE tenant_id = ?", (tenant["id"],)).fetchone()
    seal_dict = dict(seal) if seal is not None else None
    seal_ok = True
    seal_detail = "未密封（首次写入后会自动密封）"
    if seal_dict and events:
        last = events[-1]
        seal_body = _seal_bytes(
            tenant["id"], int(seal_dict["seq"]), seal_dict["final_hash"], seal_dict["sealed_at"]
        )
        seal_hash_ok = seal_dict["seal_hash"] == signing.sha256_hex(seal_body)
        seal_sig_ok = signing.verify_hex(platform_public_pem, seal_body, seal_dict["platform_sig"])
        seal_match = (
            int(seal_dict["seq"]) == int(last["seq"]) and seal_dict["final_hash"] == last["hash"]
        )
        seal_ok = bool(seal_hash_ok and seal_sig_ok and seal_match)
        seal_detail = "密封与链尾一致，签名有效" if seal_ok else "密封与链尾不一致（可能被整体重写）"
        checks.append({"id": "seal", "ok": seal_ok, "detail": seal_detail})
        if not seal_ok:
            ok = False
    elif seal_dict:
        checks.append({"id": "seal", "ok": True, "detail": "空账本密封"})

    platform_fp = signing.public_key_fingerprint(platform_public_pem)
    tenant_fp = signing.public_key_fingerprint(tenant["tenant_public_pem"])

    return {
        "result": "PASS" if ok else "FAIL",
        "records": len(events),
        "checks": checks,
        "final_hash": events[-1]["hash"] if events else GENESIS_HASH,
        "seal": {
            "present": seal_dict is not None,
            "matches": seal_ok,
            "seal_hash": seal_dict["seal_hash"] if seal_dict else None,
            "sealed_at": seal_dict["sealed_at"] if seal_dict else None,
        },
        "fingerprints": {"platform": platform_fp, "tenant": tenant_fp},
        "verified_at": now_iso(),
    }


def _record_failure(chain_ok: bool, hash_ok: bool, platform_ok: bool, tenant_ok: bool, index: int) -> str:
    problems = []
    if not chain_ok:
        problems.append("序号或前序哈希断裂（插入/删除/重排）")
    if not hash_ok:
        problems.append("记录内容与哈希不符（被编辑）")
    if not platform_ok:
        problems.append("平台签名无效")
    if not tenant_ok:
        problems.append("租户签名无效")
    return f"第 {index} 条记录：" + "；".join(problems)

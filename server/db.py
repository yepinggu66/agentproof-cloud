"""SQLite persistence for tenants, the signed ledger and scan counters.

The schema is intentionally small. One deployment = one SQLite file under
``AGENTPROOF_DATA_DIR``; a volume mount is all that is needed on Railway or
any container host. Multi-worker deployments should swap this module for a
Postgres-backed implementation (the ledger append must be serialized).
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "connect",
    "init_db",
    "insert_tenant",
    "row_to_dict",
    "a_row",
]

_LOCK = threading.Lock()
_WRITE_LOCK = _LOCK


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS tenants (
    id               TEXT PRIMARY KEY,
    company          TEXT NOT NULL,
    email            TEXT NOT NULL,
    plan             TEXT NOT NULL,
    billing          TEXT NOT NULL DEFAULT 'monthly',
    api_key_sha256   TEXT NOT NULL UNIQUE,
    api_key_prefix   TEXT NOT NULL,
    tenant_public_pem TEXT NOT NULL,
    tenant_private_enc TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS ledger (
    tenant_id      TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    id             TEXT NOT NULL,
    ts             TEXT NOT NULL,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    decision       TEXT NOT NULL,
    reason         TEXT NOT NULL,
    policy_id      TEXT NOT NULL,
    inputs_digest  TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL,
    platform_sig   TEXT NOT NULL,
    tenant_sig     TEXT NOT NULL,
    source         TEXT NOT NULL,
    PRIMARY KEY (tenant_id, seq),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ledger_tenant_ts ON ledger(tenant_id, ts);

CREATE TABLE IF NOT EXISTS seals (
    tenant_id    TEXT PRIMARY KEY,
    seq          INTEGER NOT NULL,
    final_hash   TEXT NOT NULL,
    seal_hash    TEXT NOT NULL,
    platform_sig TEXT NOT NULL,
    sealed_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id       TEXT PRIMARY KEY,
    ts       TEXT NOT NULL,
    kind     TEXT NOT NULL,
    grade    TEXT NOT NULL,
    score    INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    subject  TEXT NOT NULL
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


class write_lock:  # noqa: N801 - used as a context manager, lowercase is fine
    """Serialize ledger appends across FastAPI's threadpool workers."""

    def __enter__(self) -> "write_lock":
        _WRITE_LOCK.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        _WRITE_LOCK.release()


def a_row(row: sqlite3.Row | None) -> dict[str, Any]:
    return dict(row) if row is not None else {}


def row_to_dict(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def insert_tenant(conn: sqlite3.Connection, **fields: Any) -> None:
    columns = ", ".join(fields)
    placeholders = ", ".join(f":{name}" for name in fields)
    conn.execute(f"INSERT INTO tenants ({columns}) VALUES ({placeholders})", fields)

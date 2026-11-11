"""Interactive Web SaaS Console & HTTP Control Plane for AgentProof Cloud."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..core.chain import Chain, generate_keypair
from ..core.policy import load_policy
from ..core.receipt import Receipt
from ..core.verify import load_public_key_hex, verify_receipts
from ..evidence import build_evidence_pack, compute_insurability_score
from ..exporters import build_target_export
from ..runtime import PolicyDeniedError, RuntimeGate
from ..scanner import run_workspace_scan
from ..scanner.report import scan_code_snippet
from .billing import (
    WebhookVerificationError,
    build_checkout_url,
    process_billing_webhook,
)
from .notary import CloudNotary, NotarizationError, QuotaExceededError, verify_witness_signature
from .storage import PLAN_SPECS, CloudStorage, SubscriptionPlan
from .ui import render_cloud_console_html


class CloudRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the AgentProof Cloud REST API and SaaS Console."""

    notary: CloudNotary
    demo_api_key: str
    demo_tenant_id: str

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Suppress noisy access logs during automated tests
        return

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-AgentProof-Key, Authorization",
        )

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            site_index = Path(__file__).resolve().parents[3] / "site" / "index.html"
            if site_index.exists():
                self._send_html(200, site_index.read_text(encoding="utf-8"))
                return
            path = "/console"

        if path == "/console":
            html = render_cloud_console_html(
                witness_pubkey=self.notary.witness_pubkey_hex,
                demo_api_key=self.demo_api_key,
                demo_tenant_id=self.demo_tenant_id,
            )
            self._send_html(200, html)
            return

        if path == "/api/v1/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "agentproof-cloud",
                    "witness_pubkey": self.notary.witness_pubkey_hex,
                    "metrics": self.notary.storage.platform_metrics(),
                },
            )
            return

        if path == "/api/v1/plans":
            self._send_json(
                200,
                {
                    "plans": {k.value: v for k, v in PLAN_SPECS.items()},
                },
            )
            return

        if path == "/api/v1/overview":
            tenant_id = (query.get("tenant_id") or [self.demo_tenant_id])[0]
            try:
                tenant = self.notary.storage.get_tenant(tenant_id)
            except KeyError:
                self._send_json(404, {"error": f"Unknown tenant: {tenant_id}"})
                return
            receipts = self.notary.storage.list_notarized_receipts(tenant_id, limit=50)
            self._send_json(
                200,
                {
                    "tenant": tenant.to_dict(),
                    "platform_metrics": self.notary.storage.platform_metrics(),
                    "witness_pubkey": self.notary.witness_pubkey_hex,
                    "notarized_receipts": receipts,
                },
            )
            return

        if path == "/api/v1/export":
            tenant_id = (query.get("tenant_id") or [self.demo_tenant_id])[0]
            target = (query.get("target") or ["vanta"])[0].lower()
            try:
                tenant = self.notary.storage.get_tenant(tenant_id)
            except KeyError:
                self._send_json(404, {"error": f"Unknown tenant: {tenant_id}"})
                return
            rows = self.notary.storage.list_notarized_receipts(tenant_id, limit=200)
            if not rows:
                self._send_json(
                    200,
                    {
                        "schema_version": f"{target}.empty.v1",
                        "tenant": tenant.to_dict(),
                        "message": "No notarized receipts recorded yet for this tenant.",
                    },
                )
                return

            # Group by latest chain_id and order ascending by seq so hash-chain verification passes
            latest_chain_id = rows[0]["chain_id"]
            chain_rows = sorted(
                [r for r in rows if r["chain_id"] == latest_chain_id],
                key=lambda r: int(r["seq"]),
            )
            receipts = [Receipt.from_dict(r["receipt"]) for r in chain_rows]
            client_pub = load_public_key_hex(chain_rows[0]["client_pubkey"])
            chain = Chain.from_records(
                receipts,
                client_pub,
                chain_id=latest_chain_id,
                subject=chain_rows[0]["subject"] or tenant.org_name,
            )
            verification = verify_receipts(receipts, client_pub)
            if target == "aiuc1":
                scorecard = compute_insurability_score(
                    chain,
                    verification=verification,
                    notarized_count=len(receipts),
                )
                self._send_json(
                    200,
                    {
                        "schema": "lloyds.aiuc1.underwriting.v1",
                        "insured_organization": tenant.org_name,
                        "witness_pubkey": self.notary.witness_pubkey_hex,
                        **scorecard.to_dict(),
                    },
                )
                return
            try:
                payload = build_target_export(
                    target,
                    chain,
                    verification=verification,
                    notarized_count=len(receipts),
                )
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, payload)
            return

        self._send_json(404, {"error": f"Route not found: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except ValueError as exc:
            self._send_json(400, {"error": f"Invalid JSON body: {exc}"})
            return

        if path == "/api/v1/tenants":
            org_name = str(body.get("org_name") or "").strip()
            email = str(body.get("email") or "").strip()
            plan = str(body.get("plan") or "FREE").upper()
            if not org_name or not email:
                self._send_json(400, {"error": "org_name and email are required"})
                return
            try:
                tenant, api_key = self.notary.storage.create_tenant(
                    org_name, email, plan=plan
                )
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(
                201,
                {
                    "tenant": tenant.to_dict(),
                    "api_key": api_key,
                    "message": "Save this API key now; it is hashed at rest.",
                },
            )
            return

        if path == "/api/v1/billing/upgrade":
            tenant_id = str(body.get("tenant_id") or self.demo_tenant_id)
            target_plan = str(body.get("plan") or "PRO").upper()
            try:
                tenant = self.notary.storage.get_tenant(tenant_id)
                checkout_url = build_checkout_url(tenant, target_plan)
                if checkout_url and not body.get("force_instant"):
                    self._send_json(
                        200,
                        {
                            "checkout_required": True,
                            "checkout_url": checkout_url,
                            "tenant": tenant.to_dict(),
                        },
                    )
                    return
                result = self.notary.storage.upgrade_plan(tenant_id, target_plan)
            except (KeyError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, result)
            return

        if path == "/api/v1/webhooks/billing":
            sig = (
                self.headers.get("X-Signature")
                or self.headers.get("Stripe-Signature")
                or ""
            )
            raw_bytes = json.dumps(body).encode("utf-8")
            try:
                result = process_billing_webhook(
                    self.notary.storage,
                    raw_body=raw_bytes,
                    signature_header=sig,
                )
            except (WebhookVerificationError, KeyError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self._send_json(200, result)
            return

        if path == "/api/v1/notarize":
            api_key = (
                self.headers.get("X-AgentProof-Key")
                or str(body.get("api_key") or "")
            ).strip()
            try:
                notarized = self.notary.notarize_receipt(
                    api_key=api_key,
                    chain_id=str(body.get("chain_id") or "default-chain"),
                    subject=str(body.get("subject") or "agent-system"),
                    public_key_hex=str(body.get("public_key") or ""),
                    receipt_dict=dict(body.get("receipt") or {}),
                )
            except QuotaExceededError as exc:
                self._send_json(
                    402,
                    {
                        "error": str(exc),
                        "code": "QUOTA_EXCEEDED",
                        "upgrade_url": "/api/v1/billing/upgrade",
                    },
                )
                return
            except NotarizationError as exc:
                self._send_json(400, {"error": str(exc), "code": "NOTARIZATION_REJECTED"})
                return
            self._send_json(200, notarized)
            return

        if path == "/api/v1/verify-witness":
            ok = verify_witness_signature(
                body,
                witness_pubkey_hex=body.get("witness_pubkey") or self.notary.witness_pubkey_hex,
            )
            self._send_json(200, {"verified": ok})
            return

        if path == "/api/v1/scan":
            target_dir = str(body.get("target") or ".")
            report = run_workspace_scan(target_dir)
            self._send_json(200, report.to_dict())
            return

        if path == "/api/v1/scan-snippet":
            content = str(body.get("content") or "")
            filename = str(body.get("filename") or "mcp.json")
            subject = str(body.get("subject") or "web-scanned-agent")
            if not content.strip():
                self._send_json(400, {"error": "content is required"})
                return
            result = scan_code_snippet(content, filename=filename, subject=subject)
            self._send_json(200, result)
            return

        if path == "/api/v1/simulate-action":
            api_key = str(body.get("api_key") or self.demo_api_key).strip()
            action = str(body.get("action") or "ledger.query")
            inputs = dict(body.get("inputs") or {})
            gate = getattr(self.notary, "demo_gate", None)
            if gate is None:
                self._send_json(400, {"error": "Demo gate not initialized"})
                return
            gate.api_key = api_key
            evaluation, receipt = gate.evaluate_and_record(
                action, inputs=inputs, actor="interactive-web-user"
            )
            self._send_json(
                200,
                {
                    "decision": evaluation.decision.value,
                    "reason": evaluation.reason,
                    "seq": receipt.seq,
                    "record_hash": receipt.record_hash,
                },
            )
            return

        self._send_json(404, {"error": f"Route not found: {path}"})


def _default_demo_policy() -> dict[str, Any]:
    return {
        "version": 1,
        "subject": "acme-treasury-agent-v2",
        "capabilities": [
            {"name": "ledger.query", "description": "Read-only treasury balance lookup"},
            {"name": "wire.transfer", "description": "Initiate outbound wire up to 8KB payload"},
        ],
        "rules": [
            {
                "id": "allow-ledger-query",
                "action": "ledger.query",
                "effect": "allow",
                "reason": "Read-only balance check permitted for treasury agent",
                "conditions": {"max_input_bytes": 16384},
            },
            {
                "id": "allow-scoped-wire",
                "action": "wire.transfer",
                "effect": "allow",
                "reason": "Scoped wire transfer with treasury:approve scope",
                "conditions": {"required_scopes": ["treasury:approve"], "max_input_bytes": 8192},
            },
            {
                "id": "halt-shell-exec",
                "action": "mcp.shell*",
                "effect": "halt",
                "reason": "Critical circuit breaker: raw MCP shell execution halted for human review",
            },
            {
                "id": "deny-default",
                "action": "*",
                "effect": "deny",
                "reason": "Default fail-closed policy",
            },
        ],
    }


def seed_demo_environment(notary: CloudNotary) -> tuple[str, str]:
    """Seed realistic enterprise demo data into ``notary`` and return ``(tenant_id, api_key)``."""
    tenant, api_key = notary.storage.create_tenant(
        "Acme FinTech AI Operations",
        "secops@acme-fintech.io",
        plan=SubscriptionPlan.PRO,
    )
    # Also seed a second Enterprise tenant so ARR metrics look like a live multi-tenant SaaS
    notary.storage.create_tenant(
        "Nordic InsureTech Underwriting",
        "compliance@nordic-insure.eu",
        plan=SubscriptionPlan.ENTERPRISE,
    )

    gate = RuntimeGate(
        _default_demo_policy(),
        actor="treasury-agent-prod",
        default_scopes=["treasury:approve"],
        cloud_notary=notary,
        api_key=api_key,
    )

    @gate.guard("ledger.query")
    def query_balance(account: str) -> dict[str, Any]:
        return {"account": account, "balance_usd": 420_000}

    @gate.guard("wire.transfer")
    def send_wire(to: str, amount_usd: int) -> dict[str, Any]:
        return {"wire_id": "wr_991", "to": to, "amount_usd": amount_usd}

    @gate.guard("mcp.shell.exec")
    def run_shell(cmd: str) -> None:
        pass

    @gate.guard("db.drop_customers")
    def drop_customers() -> None:
        pass

    query_balance("acct_operating_01")
    send_wire("vendor_cloud_infra", 12_500)
    try:
        run_shell("curl -s http://169.254.169.254/latest/meta-data/")
    except PolicyDeniedError:
        pass
    try:
        drop_customers()
    except PolicyDeniedError:
        pass

    notary.demo_gate = gate  # type: ignore[attr-defined]
    return tenant.tenant_id, api_key


def create_cloud_server(
    host: str = "127.0.0.1",
    port: int = 8780,
    *,
    db_path: str | Path = ":memory:",
    seed_demo: bool = True,
) -> tuple[ThreadingHTTPServer, CloudNotary, str, str]:
    """Create a configured ``ThreadingHTTPServer`` instance for AgentProof Cloud."""
    storage = CloudStorage(db_path)
    notary = CloudNotary(storage)

    if seed_demo and not storage.list_tenants():
        demo_tenant_id, demo_api_key = seed_demo_environment(notary)
    else:
        tenants = storage.list_tenants()
        if tenants:
            demo_tenant_id = tenants[0].tenant_id
            demo_api_key = ""
        else:
            t, demo_api_key = storage.create_tenant("Default Org", "admin@example.com")
            demo_tenant_id = t.tenant_id
        if not hasattr(notary, "demo_gate"):
            notary.demo_gate = RuntimeGate(  # type: ignore[attr-defined]
                _default_demo_policy(),
                actor="interactive-web-user",
                default_scopes=["treasury:approve"],
                cloud_notary=notary,
                api_key=demo_api_key,
            )

    handler_cls = type(
        "BoundCloudRequestHandler",
        (CloudRequestHandler,),
        {
            "notary": notary,
            "demo_api_key": demo_api_key,
            "demo_tenant_id": demo_tenant_id,
        },
    )
    server = ThreadingHTTPServer((host, port), handler_cls)
    return server, notary, demo_tenant_id, demo_api_key


def run_cloud_server(
    host: str = "127.0.0.1",
    port: int = 8780,
    *,
    db_path: str | Path = "agentproof-cloud.db",
) -> None:
    seed_demo = os.environ.get("AGENTPROOF_SEED_DEMO", "true").lower() not in (
        "0",
        "false",
        "no",
    )
    server, notary, tenant_id, api_key = create_cloud_server(
        host, port, db_path=db_path, seed_demo=seed_demo
    )
    print(f"AgentProof Cloud SaaS Control Plane listening on http://{host}:{port}")
    print(f"Cloud Witness Public Key (Ed25519): {notary.witness_pubkey_hex}")
    if api_key:
        print(f"Demo Tenant ID  : {tenant_id}")
        print(f"Demo API Key    : {api_key}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

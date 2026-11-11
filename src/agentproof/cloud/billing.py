"""Stripe & LemonSqueezy Payment Checkout + Cryptographic HMAC Webhook Processor.

Allows AgentProof Cloud to accept real credit-card / Alipay / WeChat subscriptions
via LemonSqueezy (Merchant of Record, no offshore company required) or Stripe,
and automatically provision PRO ($99/mo) or ENTERPRISE ($1,500/mo) quotas upon
verified webhook callback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any
from urllib.parse import urlencode

from .storage import CloudStorage, SubscriptionPlan, TenantRecord


class WebhookVerificationError(ValueError):
    """Raised when a Stripe or LemonSqueezy webhook HMAC signature is invalid."""


def build_checkout_url(tenant: TenantRecord, target_plan: str) -> str | None:
    """Return a real hosted checkout URL if configured in env, else None (local instant mode)."""
    plan = target_plan.upper()
    env_map = {
        "PRO": os.environ.get("AGENTPROOF_CHECKOUT_PRO_URL", "").strip(),
        "ENTERPRISE": os.environ.get("AGENTPROOF_CHECKOUT_ENTERPRISE_URL", "").strip(),
    }
    base_url = env_map.get(plan)
    if not base_url:
        return None

    params = urlencode(
        {
            "checkout[custom][tenant_id]": tenant.tenant_id,
            "checkout[custom][plan]": plan,
            "checkout[email]": tenant.email,
            "client_reference_id": tenant.tenant_id,
        }
    )
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{params}"


def verify_hmac_signature(
    raw_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """Verify either a LemonSqueezy (`X-Signature` hex) or Stripe (`t=...,v1=...`) HMAC-SHA256."""
    if not secret or not signature_header:
        return False

    sig = signature_header.strip()
    # Stripe style: t=1700000000,v1=abcdef...
    if "v1=" in sig and "t=" in sig:
        parts = dict(
            item.split("=", 1) for item in sig.split(",") if "=" in item
        )
        timestamp = parts.get("t", "")
        v1 = parts.get("v1", "")
        signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
        expected = hmac.new(
            secret.encode("utf-8"), signed_payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, v1)

    # LemonSqueezy / Standard HMAC-SHA256 hex signature
    expected = hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def process_billing_webhook(
    storage: CloudStorage,
    *,
    raw_body: bytes,
    signature_header: str = "",
    webhook_secret: str | None = None,
) -> dict[str, Any]:
    """Verify and process an incoming Stripe or LemonSqueezy subscription webhook."""
    secret = (
        webhook_secret
        if webhook_secret is not None
        else os.environ.get("AGENTPROOF_WEBHOOK_SECRET", "").strip()
    )
    if secret:
        if not verify_hmac_signature(raw_body, signature_header, secret):
            raise WebhookVerificationError(
                "Invalid payment webhook HMAC signature."
            )

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except ValueError as exc:
        raise WebhookVerificationError(f"Malformed webhook JSON: {exc}") from exc

    # Extract tenant_id and plan from either LemonSqueezy (`meta.custom_data`)
    # or Stripe (`data.object.metadata` / `client_reference_id`) or direct payload
    meta_custom = (payload.get("meta") or {}).get("custom_data") or {}
    stripe_obj = (payload.get("data") or {}).get("object") or {}
    stripe_meta = stripe_obj.get("metadata") or {}

    tenant_id = (
        meta_custom.get("tenant_id")
        or stripe_meta.get("tenant_id")
        or stripe_obj.get("client_reference_id")
        or payload.get("tenant_id")
        or ""
    )
    plan_str = (
        meta_custom.get("plan")
        or stripe_meta.get("plan")
        or payload.get("plan")
        or "PRO"
    ).upper()
    payment_ref = (
        str((payload.get("data") or {}).get("id") or "")
        or str(stripe_obj.get("id") or "")
        or str(payload.get("payment_ref") or "webhook_verified")
    )

    if not tenant_id:
        raise WebhookVerificationError("Webhook payload is missing tenant_id.")

    target_plan = SubscriptionPlan(plan_str)
    return storage.upgrade_plan(
        tenant_id, target_plan, payment_ref=payment_ref
    )

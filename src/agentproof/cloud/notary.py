"""Out-of-Band Ed25519 Cloud Witness Notary for AgentProof Cloud.

Why this exists:
A local receipt chain signed on the customer's server can be rewritten from
genesis if the customer's signing key is stolen or if an insider colludes.
When a receipt is submitted to ``CloudNotary``, the Cloud Witness:
1. Authenticates the tenant API key and enforces the subscription quota.
2. Independently verifies the client's Ed25519 signature and canonical hash.
3. Counter-signs ``(tenant_id, chain_id, seq, record_hash, notarized_at)`` using
   the Cloud Witness Ed25519 private key and persists the record in the WORM ledger.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..core.canonical import canonical_bytes
from ..core.chain import generate_keypair
from ..core.receipt import Receipt
from ..core.verify import load_public_key_hex
from .storage import CloudStorage


class NotarizationError(ValueError):
    """Raised when a receipt fails client signature verification or authentication."""


class QuotaExceededError(PermissionError):
    """Raised when a tenant exceeds their monthly notarization quota (HTTP 402)."""


def _utc_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _witness_envelope(
    *,
    tenant_id: str,
    chain_id: str,
    seq: int,
    record_hash: str,
    notarized_at: str,
) -> dict[str, Any]:
    return {
        "format": "agentproof-witness-v1",
        "tenant_id": tenant_id,
        "chain_id": chain_id,
        "seq": int(seq),
        "record_hash": record_hash,
        "notarized_at": notarized_at,
    }


def verify_witness_signature(
    notarization: dict[str, Any],
    witness_pubkey_hex: str | None = None,
) -> bool:
    """Independently verify a Cloud Witness counter-signature."""
    pub_hex = witness_pubkey_hex or notarization.get("witness_pubkey", "")
    sig_hex = notarization.get("witness_signature", "")
    if not pub_hex or not sig_hex:
        return False
    try:
        pub = load_public_key_hex(pub_hex)
        envelope = _witness_envelope(
            tenant_id=str(notarization["tenant_id"]),
            chain_id=str(notarization["chain_id"]),
            seq=int(notarization["seq"]),
            record_hash=str(notarization["record_hash"]),
            notarized_at=str(notarization["notarized_at"]),
        )
        pub.verify(bytes.fromhex(sig_hex), canonical_bytes(envelope))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


class CloudNotary:
    """Multi-tenant Cloud Witness & WORM Notary engine."""

    def __init__(
        self,
        storage: CloudStorage,
        *,
        witness_private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.storage = storage
        if witness_private_key is None:
            witness_private_key, _ = generate_keypair()
        self._private_key = witness_private_key
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    @property
    def witness_pubkey_hex(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def notarize_receipt(
        self,
        *,
        api_key: str,
        chain_id: str,
        subject: str,
        public_key_hex: str,
        receipt_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Authenticate, verify client signature, enforce quota, and counter-sign."""
        tenant = self.storage.authenticate_key(api_key)
        if tenant is None:
            raise NotarizationError("Invalid or revoked X-AgentProof-Key.")

        if tenant.receipts_used >= tenant.monthly_quota:
            raise QuotaExceededError(
                f"Monthly quota exhausted ({tenant.receipts_used}/{tenant.monthly_quota}) "
                f"for plan {tenant.plan.value}. Upgrade to PRO ($99/mo) or ENTERPRISE ($1,500/mo)."
            )

        try:
            receipt = Receipt.from_dict(receipt_dict)
            client_pub = load_public_key_hex(public_key_hex)
        except (ValueError, KeyError, TypeError) as exc:
            raise NotarizationError(f"Malformed receipt or public key: {exc}") from exc

        expected_hash = receipt.compute_hash()
        if receipt.record_hash != expected_hash:
            raise NotarizationError(
                f"Receipt record_hash mismatch: expected {expected_hash}, got {receipt.record_hash}"
            )

        try:
            client_pub.verify(
                bytes.fromhex(receipt.signature),
                bytes.fromhex(receipt.record_hash),
            )
        except (InvalidSignature, ValueError) as exc:
            raise NotarizationError(
                "Client Ed25519 signature verification failed; refusing to notarize forged receipt."
            ) from exc

        notary_id = f"ntr_{uuid.uuid4().hex[:14]}"
        notarized_at = _utc_iso()
        envelope = _witness_envelope(
            tenant_id=tenant.tenant_id,
            chain_id=chain_id,
            seq=receipt.seq,
            record_hash=receipt.record_hash,
            notarized_at=notarized_at,
        )
        witness_sig = self._private_key.sign(canonical_bytes(envelope)).hex()

        self.storage.store_notarized_receipt(
            notary_id=notary_id,
            tenant_id=tenant.tenant_id,
            chain_id=chain_id,
            subject=subject,
            seq=receipt.seq,
            record_hash=receipt.record_hash,
            actor=receipt.actor,
            action=receipt.action,
            decision=receipt.decision.value,
            reason=receipt.reason,
            issued_at=receipt.issued_at,
            notarized_at=notarized_at,
            client_pubkey=public_key_hex,
            witness_pubkey=self.witness_pubkey_hex,
            witness_signature=witness_sig,
            receipt_dict=receipt.to_dict(),
        )

        return {
            "notary_id": notary_id,
            "tenant_id": tenant.tenant_id,
            "chain_id": chain_id,
            "seq": receipt.seq,
            "record_hash": receipt.record_hash,
            "notarized_at": notarized_at,
            "witness_pubkey": self.witness_pubkey_hex,
            "witness_signature": witness_sig,
            "status": "NOTARIZED",
        }

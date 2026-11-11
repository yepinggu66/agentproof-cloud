"""Ed25519 signing primitives for the AgentProof.cloud ledger.

Every ledger record is signed twice: once by the platform key (AgentProof
attests that it issued the receipt before the action) and once by the
tenant key (the customer attests that the receipt belongs to their agent).
Both signatures cover the same canonical bytes.

No network, no KMS, no dependency beyond ``cryptography``. Keys live under
``AGENTPROOF_DATA_DIR``; tenant private keys are encrypted at rest with a
locally generated Fernet master key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "canonical_bytes",
    "sha256_hex",
    "generate_keypair_pem",
    "private_key_from_pem",
    "public_key_from_pem",
    "public_key_fingerprint",
    "sign_hex",
    "verify_hex",
    "load_master_key",
    "encrypt_private_key",
    "decrypt_private_key",
]

_CANONICAL_ENCODING = "utf-8"


def canonical_bytes(payload: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8.

    This is the byte sequence that gets hashed and signed. Any change to a
    field changes the bytes and invalidates both signatures.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode(_CANONICAL_ENCODING)


def sha256_hex(data: Any) -> str:
    """SHA-256 hex of bytes, text, or any canonicalizable JSON value."""
    if isinstance(data, str):
        data = data.encode(_CANONICAL_ENCODING)
    elif not isinstance(data, (bytes, bytearray, memoryview)):
        data = canonical_bytes(data)
    return hashlib.sha256(bytes(data)).hexdigest()


def generate_keypair_pem() -> tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)`` for a fresh Ed25519 key."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def private_key_from_pem(pem: bytes | str) -> Ed25519PrivateKey:
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def public_key_from_pem(pem: bytes | str) -> Ed25519PublicKey:
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def public_key_fingerprint(public_pem: bytes | str) -> str:
    """SHA-256 over the raw 32-byte public key, hex encoded.

    This is the value shown as the "公钥指纹" in the console: short enough to
    eyeball, strong enough to compare out of band.
    """
    key = public_key_from_pem(public_pem)
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_hex(private_pem: bytes | str, data: bytes) -> str:
    private_key = private_key_from_pem(private_pem)
    return private_key.sign(data).hex()


def verify_hex(public_pem: bytes | str, data: bytes, signature_hex: str) -> bool:
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        public_key_from_pem(public_pem).verify(signature, data)
    except Exception:  # cryptography raises InvalidSignature, but be defensive
        return False
    return True


# ---------------------------------------------------------------------------
# at-rest encryption for tenant private keys
# ---------------------------------------------------------------------------


def load_master_key(data_dir: Path) -> Fernet:
    """Load (or create) the local master key used to encrypt tenant keys."""
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / "master.key"
    if key_path.exists():
        raw = key_path.read_bytes().strip()
    else:
        raw = Fernet.generate_key()
        key_path.write_bytes(raw + b"\n")
        try:
            os.chmod(key_path, 0o600)
        except OSError:  # pragma: no cover - Windows ACLs differ
            pass
    return Fernet(raw)


def encrypt_private_key(master: Fernet, private_pem: bytes) -> str:
    return master.encrypt(private_pem).decode("ascii")


def decrypt_private_key(master: Fernet, token: str) -> bytes:
    return master.decrypt(token.encode("ascii"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

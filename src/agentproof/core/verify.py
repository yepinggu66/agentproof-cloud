"""Offline verification.

An auditor should be able to check your evidence without running your code,
without trusting your server, and without a network connection. That is what
this module provides: given a chain file and a public key, it answers
"was this record set altered?" and "does every decision carry a valid
signature?"

What verification can and cannot establish
--------------------------------------------
**It can establish** that no record was edited, inserted, deleted, or
reordered relative to the sealed anchor; that every signature is valid; that
the chain contains no replayed nonce; and that the seal matches the chain.

**It cannot establish** that a record was never fabricated in the first
place. If the signing key itself was used to write a false decision and then
the chain was sealed honestly, verification passes. That is inherent to any
signature scheme and is why the signing key is the thing you must protect:
keep it in an HSM or a passphrase-protected file, never in the repo.

The one thing a hash chain alone cannot catch is a *complete* rewrite by
someone holding the signing key: every record re-signed end to end verifies
internally and looks perfectly consistent. The seal exists for that case.
When a seal is supplied, verification compares it against the chain; a
mismatch means the chain was rewritten after sealing. Publish the seal
out-of-band (email it to yourself, commit it to a different repository) or
this protection is void.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._textio import TextDecodeError, decode_text
from .canonical import digest_bytes
from .chain import Seal
from .receipt import Receipt

__all__ = [
    "VerificationResult",
    "verify_chain_file",
    "verify_chain_data",
    "verify_receipts",
    "load_public_key_hex",
]


@dataclass
class VerificationResult:
    """Outcome of a verification run."""

    ok: bool
    records_checked: int = 0
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    chain_id: str = ""
    final_hash: str = ""
    seal_present: bool = False
    seal_matches: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records_checked": self.records_checked,
            "problems": self.problems,
            "warnings": self.warnings,
            "chain_id": self.chain_id,
            "final_hash": self.final_hash,
            "seal_present": self.seal_present,
            "seal_matches": self.seal_matches,
        }

    def render(self) -> str:
        """Human-readable summary suitable for a terminal or a report."""
        lines: list[str] = []
        lines.append(f"chain_id      : {self.chain_id or '(none)'}")
        lines.append(f"records       : {self.records_checked}")
        lines.append(f"final hash    : {self.final_hash or '(none)'}")
        lines.append(
            "seal          : "
            + (
                "present, matches"
                if self.seal_present and self.seal_matches
                else "present, DOES NOT MATCH"
                if self.seal_present
                else "absent (rewrite detection unavailable)"
            )
        )
        lines.append(f"result        : {'PASS' if self.ok else 'FAIL'}")
        if self.problems:
            lines.append("")
            lines.append("problems:")
            lines.extend(f"  - {p}" for p in self.problems)
        if self.warnings:
            lines.append("")
            lines.append("warnings:")
            lines.extend(f"  - {w}" for w in self.warnings)
        return "\n".join(lines)


def load_public_key_hex(key_hex: str) -> Ed25519PublicKey:
    """Build a public key from its raw hex encoding."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))


def _public_key_raw_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_public_key_file(path: str | Path) -> Ed25519PublicKey:
    """Load a public key from a PEM or raw-hex file.

    PEM is what ``agentproof keygen`` writes (and what ``cli.py verify --key``
    already assumes); a plain hex file is accepted as a convenience for
    keys published in documentation or copied out of a chain document.
    """
    key_path = Path(path)
    raw = key_path.read_bytes()

    try:
        candidate = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError):
        candidate = None
    if candidate is not None:
        if not isinstance(candidate, Ed25519PublicKey):
            raise ValueError(
                f"public key file {key_path} contains a "
                f"{type(candidate).__name__}; expected an Ed25519 public key"
            )
        return candidate

    try:
        key_hex = decode_text(raw, path=key_path, kind="public key").strip()
    except TextDecodeError as exc:
        raise ValueError(str(exc)) from exc
    try:
        return load_public_key_hex(key_hex)
    except ValueError as exc:
        raise ValueError(
            f"public key file {key_path} is neither a PEM public key nor a "
            f"hex-encoded Ed25519 public key: {exc}"
        ) from exc


def _verify_receipt_signature(
    receipt: Receipt, public_key: Ed25519PublicKey
) -> bool:
    if not receipt.signature or not receipt.record_hash:
        return False
    try:
        public_key.verify(
            bytes.fromhex(receipt.signature),
            bytes.fromhex(receipt.record_hash),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_receipts(
    receipts: list[Receipt],
    public_key: Ed25519PublicKey,
    *,
    seal: Seal | None = None,
) -> VerificationResult:
    """Verify a list of receipts against ``public_key``.

    Checks, in order:
      1. sequence numbers are contiguous from 0
      2. each receipt's stored hash matches a recomputation of its body
      3. each receipt's ``prev_hash`` equals the previous receipt's hash
      4. each receipt's signature verifies
      5. no nonce appears twice
      6. if a seal is present, it matches the chain
    """
    problems: list[str] = []
    warnings: list[str] = []

    # 1. sequence continuity
    for index, receipt in enumerate(receipts):
        if receipt.seq != index:
            problems.append(
                f"record #{index} has seq {receipt.seq}; expected {index}. "
                "A gap or reordering means a record was inserted or removed."
            )

    # 2. hash integrity
    for receipt in receipts:
        recomputed = receipt.compute_hash()
        if recomputed != receipt.record_hash:
            problems.append(
                f"seq {receipt.seq}: stored hash does not match the receipt body. "
                "The record was altered after signing."
            )

    # 3. chain linkage
    prev = ""
    for receipt in receipts:
        if receipt.prev_hash != prev:
            problems.append(
                f"seq {receipt.seq}: prev_hash does not match the previous "
                "record's hash. The chain link is broken."
            )
        prev = receipt.record_hash

    # 4. signatures
    for receipt in receipts:
        if not _verify_receipt_signature(receipt, public_key):
            problems.append(
                f"seq {receipt.seq}: signature does not verify against the "
                "supplied public key."
            )

    # 5. nonce uniqueness
    seen: dict[str, int] = {}
    for receipt in receipts:
        if receipt.nonce in seen:
            problems.append(
                f"seq {receipt.seq}: nonce repeats the one used at seq "
                f"{seen[receipt.nonce]}. A step was replayed."
            )
        else:
            seen[receipt.nonce] = receipt.seq

    result = VerificationResult(
        ok=not problems,
        records_checked=len(receipts),
        problems=problems,
        warnings=warnings,
        chain_id=seal.chain_id if seal else "",
        final_hash=receipts[-1].record_hash if receipts else "",
        seal_present=seal is not None,
    )

    # 6. seal comparison
    if seal is not None:
        expected_seal_hash = digest_bytes(
            {
                "chain_id": seal.chain_id,
                "sealed_at": seal.sealed_at,
                "record_count": seal.record_count,
                "final_hash": seal.final_hash,
            }
        )
        seal_problems: list[str] = []

        if expected_seal_hash != seal.seal_hash:
            seal_problems.append(
                "the seal's own hash does not match its contents; the seal was "
                "modified after signing"
            )
        if seal.signature:
            try:
                public_key.verify(
                    bytes.fromhex(seal.signature),
                    bytes.fromhex(seal.seal_hash),
                )
            except (InvalidSignature, ValueError):
                seal_problems.append("the seal's signature does not verify")
        else:
            seal_problems.append("the seal carries no signature")

        if seal.record_count != len(receipts):
            seal_problems.append(
                f"the seal covers {seal.record_count} records but the file "
                f"contains {len(receipts)}"
            )
        if receipts and seal.final_hash != receipts[-1].record_hash:
            seal_problems.append(
                "the seal's final hash does not match the last record. "
                "The chain was rewritten after it was sealed."
            )
        if not receipts and seal.final_hash:
            seal_problems.append(
                "the seal references a final hash but the chain is empty"
            )

        result.seal_matches = not seal_problems
        result.problems.extend(seal_problems)
        result.ok = not result.problems
    else:
        result.warnings.append(
            "no seal was supplied. A complete rewrite of the chain by someone "
            "holding the signing key cannot be detected without an out-of-band "
            "anchor. Publish the seal separately."
        )

    return result


def verify_chain_data(
    data: dict[str, Any], public_key: Ed25519PublicKey
) -> VerificationResult:
    """Verify an in-memory chain document.

    A document that cannot even be deserialized is reported as a failed
    verification rather than raised: an auditor running a batch of chain files
    must get "this file is broken" for the broken one, not a crash that hides
    the verdicts for all the others.
    """
    if not isinstance(data, dict):
        return VerificationResult(
            ok=False,
            problems=[
                "malformed chain document: expected a JSON object, got "
                f"{type(data).__name__}"
            ],
        )

    try:
        records_data = data.get("records") or []
        if not isinstance(records_data, list):
            raise ValueError(
                f"'records' must be a list, got {type(records_data).__name__}"
            )
        records = [Receipt.from_dict(record) for record in records_data]
        seal_data = data.get("seal")
        seal = Seal.from_dict(seal_data) if seal_data else None
    except (TypeError, ValueError, KeyError) as exc:
        return VerificationResult(
            ok=False,
            problems=[f"malformed chain document: {exc}"],
            chain_id=str(data.get("chain_id") or ""),
        )

    result = verify_receipts(records, public_key, seal=seal)
    result.chain_id = data.get("chain_id", "") or result.chain_id
    return result


def verify_chain_file(
    path: str | Path,
    public_key: Ed25519PublicKey | None = None,
    *,
    key_path: str | Path | None = None,
) -> VerificationResult:
    """Verify a chain file on disk.

    The verification key is resolved in this order, strongest source first:

    1. ``public_key`` / ``key_path`` supplied by the caller — i.e. a key
       obtained out-of-band, which is the only way to detect a chain whose
       embedded key was replaced;
    2. the ``public_key`` field embedded in the chain document, which proves
       internal consistency only.

    ``key_path`` takes precedence over the embedded field, and may point at a
    PEM public key (what ``agentproof keygen`` writes) or at a hex-encoded raw
    key. If the caller supplies both ``public_key`` and ``key_path`` and they
    do not identify the same key, that is a usage error rather than something
    to guess about.
    """
    chain_path = Path(path)
    if not chain_path.exists():
        raise FileNotFoundError(f"chain file not found: {chain_path}")

    raw = chain_path.read_bytes()
    try:
        text = decode_text(raw, path=chain_path, kind="chain")
    except TextDecodeError as exc:
        raise ValueError(str(exc)) from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(
            f"chain file {chain_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"chain file {chain_path} must contain a JSON object, got "
            f"{type(data).__name__}"
        )

    embedded_key: Ed25519PublicKey | None = None
    embedded_error: str | None = None
    embedded_hex = data.get("public_key")
    if embedded_hex:
        try:
            embedded_key = load_public_key_hex(str(embedded_hex))
        except (TypeError, ValueError) as exc:
            embedded_error = (
                f"chain file {chain_path} has an unreadable 'public_key' "
                f"field: {exc}"
            )

    from_file: Ed25519PublicKey | None = None
    if key_path is not None:
        from_file = _load_public_key_file(key_path)

    if from_file is not None and public_key is not None:
        if _public_key_raw_bytes(from_file) != _public_key_raw_bytes(public_key):
            raise ValueError(
                "public_key= and key_path= identify different keys; refusing "
                "to guess which one is the intended trust anchor"
            )
        verification_key = public_key
    elif from_file is not None:
        verification_key = from_file
    elif public_key is not None:
        verification_key = public_key
    elif embedded_key is not None:
        verification_key = embedded_key
    elif embedded_error is not None:
        raise ValueError(embedded_error)
    else:
        raise ValueError(
            "no public key available: pass public_key= or key_path=, or "
            "include a 'public_key' field in the chain file"
        )

    result = verify_chain_data(data, verification_key)
    result.chain_id = data.get("chain_id", "") or result.chain_id

    if embedded_error is not None:
        result.warnings.append(
            f"{embedded_error}. It was ignored because a key was supplied for "
            "verification; the signatures were checked against that key."
        )
    elif embedded_key is not None and (
        _public_key_raw_bytes(embedded_key)
        != _public_key_raw_bytes(verification_key)
    ):
        result.warnings.append(
            "the public key embedded in the chain file differs from the key "
            "supplied for verification. Signatures were checked against the "
            "supplied key, which is what a real audit requires; the embedded "
            "key is untrusted input."
        )

    return result

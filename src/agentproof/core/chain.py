"""Append-only hash chain with Ed25519 signatures.

Design constraints, in priority order:

1. **Append-only.** The chain only grows. :meth:`Chain.append` is the sole
   mutator; there is no update or delete.
2. **Pre-execution signing.** A receipt is signed and hashed *before* the
   action it authorizes is allowed to run.
3. **Tamper-evident, not tamper-proof.** We cannot stop the holder of the
   signing key from rewriting history. What we can do is make every rewrite
   visible to anyone holding the sealed anchor. See :func:`Chain.seal` and
   the module docstring of :mod:`agentproof.core.verify`.
4. **Fail closed.** Any error raises. A chain never silently skips a step.

The tamper-evidence argument
----------------------------
A hash chain where each record includes the previous record's hash makes
three kinds of tampering visible:

* **Field edit** — editing receipt #3 changes its hash, which no longer
  matches ``record_hash``, and also breaks the link to receipt #4.
* **Insertion** — inserting a receipt shifts every subsequent ``seq`` and
  breaks the ``prev_hash`` link.
* **Deletion** — removing receipt #3 breaks receipt #4's ``prev_hash`` link.

The one case a chain cannot catch on its own: an attacker who holds the
signing key can rewrite the *entire* chain and re-sign every record, and it
will verify internally. That is why :meth:`Chain.seal` exists — the seal is an
anchor published out-of-band (email, timestamped service, your own storage)
that the rewritten chain cannot forge. :func:`agentproof.core.verify.verify`
compares against the seal when one is available and reports the rewrite.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._textio import TextDecodeError, decode_text
from .canonical import digest, digest_bytes
from .receipt import Decision, Receipt, new_nonce, utc_now

__all__ = [
    "Chain",
    "ChainError",
    "Seal",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
]


class ChainError(RuntimeError):
    """Raised on any chain invariant violation. Never swallowed."""


@dataclass(frozen=True)
class Seal:
    """An out-of-band anchor for a chain segment.

    The seal binds the final record hash, the record count, and the chain
    identity. Publishing the seal outside the chain file (email it to
    yourself, commit it to a separate repository, print it) is what makes a
    full re-sign detectable.
    """

    chain_id: str
    sealed_at: str
    record_count: int
    final_hash: str
    seal_hash: str
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "sealed_at": self.sealed_at,
            "record_count": self.record_count,
            "final_hash": self.final_hash,
            "seal_hash": self.seal_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Seal":
        if not isinstance(data, dict):
            raise ValueError(f"seal must be a mapping, got {type(data).__name__}")
        return cls(
            chain_id=str(data["chain_id"]),
            sealed_at=str(data["sealed_at"]),
            record_count=int(data["record_count"]),
            final_hash=str(data["final_hash"]),
            seal_hash=str(data["seal_hash"]),
            signature=str(data.get("signature", "")),
        )


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def load_private_key(path: str | Path, password: bytes | None = None) -> Ed25519PrivateKey:
    """Load a PEM private key from disk."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ChainError("expected an Ed25519 private key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load a PEM public key from disk."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ChainError("expected an Ed25519 public key")
    return key


def _canonical_path(path: str | Path) -> str:
    """A path identity suitable for comparing load/save targets on Windows."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Chain:
    """An append-only, signed, hash-chained sequence of decision receipts."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        chain_id: str | None = None,
        *,
        subject: str = "",
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.chain_id = chain_id or digest_bytes(
            {"issued_at": utc_now().isoformat(), "nonce": new_nonce()}
        )[:16]
        self.subject = subject
        self._receipts: list[Receipt] = []
        self._seen_nonces: set[str] = set()
        self._sealed: Seal | None = None
        # Where this in-memory chain last came from / went to, plus the digest
        # of the exact bytes involved. save() uses the digest to notice that
        # another process replaced the file since it was loaded; without that
        # check a read-modify-write append silently drops the other writer's
        # signed receipt.
        self._persisted_path: str | None = None
        self._persisted_digest: str | None = None

    # ------------------------------------------------------------------
    # introspection
    # ------------------------------------------------------------------
    @property
    def receipts(self) -> tuple[Receipt, ...]:
        return tuple(self._receipts)

    @property
    def sealed(self) -> bool:
        return self._sealed is not None

    @property
    def seal(self) -> Seal | None:
        return self._sealed

    @property
    def final_hash(self) -> str:
        """Hash of the last record, or the genesis marker for an empty chain."""
        return self._receipts[-1].record_hash if self._receipts else ""

    def __len__(self) -> int:
        return len(self._receipts)

    # ------------------------------------------------------------------
    # mutation
    # ------------------------------------------------------------------
    def append(
        self,
        *,
        actor: str,
        action: str,
        decision: Decision,
        reason: str,
        policy_id: str,
        policy_digest: str,
        inputs_digest: str,
        context: dict[str, Any] | None = None,
        nonce: str | None = None,
    ) -> Receipt:
        """Append a signed receipt and return it.

        The receipt is signed over the body that includes ``prev_hash``, so
        it is impossible to append a record without extending the chain.
        """
        if self._sealed is not None:
            raise ChainError(
                "chain is sealed; a sealed chain is immutable and cannot accept "
                "new records"
            )

        # Coerce and validate the decision up front. A malformed decision must
        # fail loudly here rather than produce a receipt that later explodes
        # during serialization — or worse, gets recorded as something the
        # caller did not intend.
        if isinstance(decision, str):
            try:
                decision = Decision(decision.upper())
            except ValueError as exc:
                raise ChainError(
                    f"invalid decision {decision!r}; expected one of "
                    f"{[d.value for d in Decision]}"
                ) from exc
        elif not isinstance(decision, Decision):
            raise ChainError(
                f"decision must be a Decision or a string, got "
                f"{type(decision).__name__}"
            )

        used_nonce = nonce or new_nonce()
        if used_nonce in self._seen_nonces:
            raise ChainError(
                f"nonce {used_nonce!r} already used in this chain; "
                "refusing to record a replayed step"
            )

        draft = Receipt(
            seq=len(self._receipts),
            nonce=used_nonce,
            issued_at=utc_now().isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            actor=actor,
            action=action,
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            policy_digest=policy_digest,
            inputs_digest=inputs_digest,
            context=dict(context or {}),
            prev_hash=self.final_hash,
        )

        record_hash = draft.compute_hash()
        signature = self._private_key.sign(
            bytes.fromhex(record_hash)
        ).hex()

        receipt = draft.with_signature(signature=signature, record_hash=record_hash)
        self._receipts.append(receipt)
        self._seen_nonces.add(used_nonce)
        return receipt

    def seal_chain(self) -> Seal:
        """Close the chain and produce an out-of-band anchor.

        After sealing, no further records can be appended.
        """
        if self._sealed is not None:
            raise ChainError("chain is already sealed")
        if not self._receipts:
            raise ChainError("cannot seal an empty chain")

        body = {
            "chain_id": self.chain_id,
            "sealed_at": utc_now().isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "record_count": len(self._receipts),
            "final_hash": self.final_hash,
        }
        seal_hash = digest_bytes(body)
        signature = self._private_key.sign(bytes.fromhex(seal_hash)).hex()

        self._sealed = Seal(**body, seal_hash=seal_hash, signature=signature)
        return self._sealed

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "agentproof-chain-v1",
            "chain_id": self.chain_id,
            "subject": self.subject,
            "public_key": self._public_key_bytes().hex(),
            "records": [r.to_dict() for r in self._receipts],
            "seal": self._sealed.to_dict() if self._sealed else None,
        }

    def save(self, path: str | Path) -> Path:
        """Write the chain to ``path`` atomically and fail closed on a race.

        Two guarantees matter here:

        * **No torn files.** The document is written to a temporary file in
          the same directory and moved into place with :func:`os.replace`, so
          a crash mid-write cannot truncate an existing evidence chain.
        * **No silent lost updates.** If this chain was loaded from ``path``
          and another process has rewritten that file since, saving would
          silently overwrite its records. We re-read the file and compare its
          digest to the one captured at load time; on a mismatch we raise
          :class:`ChainError` and leave the other writer's data intact.

        Saving a freshly created chain (or saving to a different path) is not
        a read-modify-write and is not guard-checked.
        """
        out = Path(path)
        target = _canonical_path(out)

        if self._persisted_path == target and self._persisted_digest is not None:
            try:
                current = _file_digest(out)
            except FileNotFoundError as exc:
                raise ChainError(
                    f"chain file {out} was deleted since it was loaded; "
                    "refusing to recreate it here because that would discard "
                    "records another process may have written"
                ) from exc
            except OSError as exc:
                raise ChainError(
                    f"cannot re-read chain file {out} to confirm no other "
                    f"process is writing it, so refusing to overwrite: {exc}"
                ) from exc
            if current != self._persisted_digest:
                raise ChainError(
                    f"chain file {out} was modified by another process after "
                    "it was loaded (concurrent append?); refusing to overwrite "
                    "it and lose that record. Reload the chain and retry."
                )

        payload = json.dumps(
            self.to_dict(), indent=2, ensure_ascii=False, sort_keys=True
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(
            prefix=f".{out.name}.", suffix=".tmp", dir=str(out.parent)
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            digest_of_new_file = _file_digest(Path(temp_name))
            os.replace(temp_name, out)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

        self._persisted_path = target
        self._persisted_digest = digest_of_new_file
        return out

    @classmethod
    def load(cls, path: str | Path, private_key: Ed25519PrivateKey) -> "Chain":
        source = Path(path)
        raw = source.read_bytes()
        try:
            text = decode_text(raw, path=source, kind="chain")
        except TextDecodeError as exc:
            raise ChainError(str(exc)) from exc
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ChainError(f"chain file {source} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ChainError(
                f"chain file {source} must contain a JSON object, got "
                f"{type(data).__name__}"
            )
        chain = cls(
            private_key,
            chain_id=data.get("chain_id"),
            subject=data.get("subject", ""),
        )
        records = data.get("records") or []
        if not isinstance(records, list):
            raise ChainError(f"chain file {source} has a non-list 'records' field")
        for record in records:
            try:
                receipt = Receipt.from_dict(record)
            except (TypeError, ValueError, KeyError) as exc:
                raise ChainError(
                    f"chain file {source} contains a malformed record: {exc}"
                ) from exc
            chain._receipts.append(receipt)
            chain._seen_nonces.add(receipt.nonce)
        seal_data = data.get("seal")
        if seal_data:
            try:
                chain._sealed = Seal.from_dict(seal_data)
            except (TypeError, ValueError, KeyError) as exc:
                raise ChainError(
                    f"chain file {source} contains a malformed seal: {exc}"
                ) from exc
        chain._persisted_path = _canonical_path(source)
        chain._persisted_digest = hashlib.sha256(raw).hexdigest()
        return chain

    @classmethod
    def from_records(
        cls,
        receipts: list[Receipt],
        public_key: Ed25519PublicKey,
        *,
        chain_id: str = "",
        subject: str = "",
        seal: Seal | None = None,
    ) -> "Chain":
        """Rebuild a read-only chain from raw records and a public key.

        No private key is required, so a third party (auditor, buyer,
        regulator) can reconstruct and inspect a chain without being trusted
        with the ability to extend it.
        """
        chain = cls.__new__(cls)
        chain._private_key = None  # type: ignore[assignment]
        chain._public_key = public_key
        chain.chain_id = chain_id
        chain.subject = subject
        chain._receipts = list(receipts)
        chain._seen_nonces = {r.nonce for r in receipts}
        chain._sealed = seal
        chain._persisted_path = None
        chain._persisted_digest = None
        return chain

    def _public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_hex(self) -> str:
        return self._public_key_bytes().hex()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The chain's public key, for offline verification by third parties."""
        return self._public_key

    def verify_signatures(self) -> list[str]:
        """Return a list of problems found in the signature layer.

        Empty list means every record's signature checks out against the
        chain's public key.
        """
        problems: list[str] = []
        for receipt in self._receipts:
            if not receipt.signature:
                problems.append(f"seq {receipt.seq}: missing signature")
                continue
            try:
                self._public_key.verify(
                    bytes.fromhex(receipt.signature),
                    bytes.fromhex(receipt.record_hash),
                )
            except (InvalidSignature, ValueError):
                problems.append(f"seq {receipt.seq}: signature does not verify")
        return problems

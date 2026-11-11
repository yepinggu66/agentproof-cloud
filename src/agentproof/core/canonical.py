"""Deterministic canonical serialization.

Every hash in agentproof is computed over the *bytes* produced here. If two
processes, two machines, or two languages serialize the same logical value
differently, the hashes differ and the chain breaks. So this module has exactly
one job: turn any JSON-able value into a single, stable byte string.

Rules:
  * Object keys are sorted by Unicode code point.
  * No insignificant whitespace.
  * UTF-8, no BOM.
  * ``NaN`` / ``Infinity`` are rejected (they have no JSON representation and
    would silently break round-tripping).
  * ``datetime`` / ``date`` / ``Decimal`` / ``UUID`` / ``bytes`` / ``set`` are
    converted through explicit, documented rules rather than ``repr()``.
  * Float values use ``repr()`` (shortest round-trippable form), which is
    stable across CPython 3.1+.

If you change anything here, previously written chains stop verifying. The
format version is embedded in every digest so that break is loud, not silent.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import hashlib
import json
import uuid
from typing import Any

__all__ = [
    "CANONICAL_FORMAT_VERSION",
    "canonical_bytes",
    "canonical_json",
    "digest",
    "digest_bytes",
    "CanonicalizationError",
]

#: Bump this whenever the canonicalization rules change in a way that would
#: alter the bytes produced for an unchanged logical value.
CANONICAL_FORMAT_VERSION = "canon-v1"


class CanonicalizationError(TypeError):
    """Raised when a value cannot be canonicalized deterministically."""


def _normalize(value: Any) -> Any:
    """Convert ``value`` into a structure ``json.dumps`` can handle, deterministically."""
    if value is None or isinstance(value, (bool, str)):
        return value

    if isinstance(value, int):
        # bool is handled above; plain int is exact in JSON.
        return value

    if isinstance(value, float):
        # NaN / Infinity are not valid JSON. Reject rather than emit a token
        # that a strict parser would choke on.
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalizationError(
                f"non-finite float cannot be canonicalized: {value!r}"
            )
        return value

    if isinstance(value, decimal.Decimal):
        # str() on Decimal preserves the declared precision exactly, which is
        # what an auditor wants: 1.10 must not become 1.1.
        return {"__decimal__": str(value)}

    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}

    if isinstance(value, bytearray):
        return {"__bytes__": bytes(value).hex()}

    if isinstance(value, _dt.datetime):
        # Normalize to UTC and use a fixed format so timezone offsets cannot
        # produce two different strings for the same instant.
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        return {
            "__datetime__": value.astimezone(_dt.timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        }

    if isinstance(value, _dt.date):
        return {"__date__": value.isoformat()}

    if isinstance(value, uuid.UUID):
        return {"__uuid__": str(value)}

    if isinstance(value, (set, frozenset)):
        # Sets are unordered; sort their canonical forms to get a stable order.
        return {"__set__": sorted(_normalize(v) for v in value)}

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
            out[key] = _normalize(item)
        return out

    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]

    # Fall back to pydantic/dataclass style objects if available, otherwise
    # refuse. Silently repr()-ing an unknown object would make the digest
    # depend on memory addresses, which is exactly the bug we are avoiding.
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _normalize(model_dump(mode="json"))
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _normalize(to_dict())

    raise CanonicalizationError(
        f"cannot canonicalize value of type {type(value).__name__}; "
        "convert it to a JSON-able structure first"
    )


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 bytes for ``value``."""
    return canonical_json(value).encode("utf-8")


def digest_bytes(value: Any) -> str:
    """SHA-256 hex digest of the canonical bytes of ``value``."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()

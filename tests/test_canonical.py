"""Canonicalization must be deterministic or every hash in the system is meaningless."""

from __future__ import annotations

import datetime as dt
import decimal

import pytest

from agentproof.core.canonical import (
    CanonicalizationError,
    canonical_bytes,
    canonical_json,
    digest_bytes,
)


def test_key_order_does_not_matter():
    a = {"b": 1, "a": 2, "c": {"z": 1, "y": 2}}
    b = {"c": {"y": 2, "z": 1}, "a": 2, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert digest_bytes(a) == digest_bytes(b)


def test_list_order_does_matter():
    assert canonical_bytes([1, 2]) != canonical_bytes([2, 1])


def test_no_insignificant_whitespace():
    assert canonical_json({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_unicode_is_preserved_not_escaped():
    result = canonical_json({"reason": "已拒绝：超出权限范围"})
    assert "已拒绝" in result
    assert "\\u" not in result


def test_non_finite_float_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": float("inf")})


def test_decimal_preserves_declared_precision():
    assert canonical_json(decimal.Decimal("1.10")) == '{"__decimal__":"1.10"}'
    assert canonical_json(decimal.Decimal("1.1")) == '{"__decimal__":"1.1"}'


def test_datetime_normalized_to_utc():
    naive = dt.datetime(2026, 10, 27, 12, 0, 0)
    aware = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert canonical_bytes(naive) == canonical_bytes(aware)


def test_bytes_become_hex():
    assert canonical_json(b"\x00\xff") == '{"__bytes__":"00ff"}'


def test_set_is_sorted():
    assert canonical_json({3, 1, 2}) == '{"__set__":[1,2,3]}'


def test_non_string_key_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({1: "a"})


def test_unserializable_type_is_rejected_not_guessed():
    class Weird:
        def __repr__(self) -> str:
            return "<Weird object at 0x7f00>"

    with pytest.raises(CanonicalizationError):
        canonical_bytes({"x": Weird()})


def test_digest_is_stable_across_calls():
    payload = {"action": "kb.search", "inputs": {"q": "refund"}}
    assert digest_bytes(payload) == digest_bytes(dict(payload))

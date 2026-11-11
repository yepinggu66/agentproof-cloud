"""Tamper detection.

These tests are the product's central claim: an altered chain must be
detectable by a third party holding only the public key.

Each test mutates a sealed chain in one specific way and asserts that
verification fails. If any of these silently passes, the product does not
do what it advertises.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentproof.core.chain import Chain
from agentproof.core.receipt import Receipt
from agentproof.core.verify import verify_chain_file, verify_receipts


def _write(chain: Chain, path: Path) -> Path:
    chain.save(path)
    return path


def _load_raw(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_raw(data: dict, path: Path) -> Path:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


# ----------------------------------------------------------------------
# the happy path
# ----------------------------------------------------------------------
def test_unmodified_sealed_chain_verifies(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    result = verify_chain_file(path)

    assert result.ok
    assert result.problems == []
    assert result.records_checked == 3
    assert result.seal_present
    assert result.seal_matches


def test_unsealed_chain_verifies_but_warns(populated_chain, tmp_path):
    path = _write(populated_chain, tmp_path / "chain.json")

    result = verify_chain_file(path)

    assert result.ok
    assert result.seal_present is False
    assert any("seal" in w.lower() for w in result.warnings)


# ----------------------------------------------------------------------
# tampering
# ----------------------------------------------------------------------
def test_edited_field_is_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    # Change the reason on a decision, leaving the stored hash alone.
    data["records"][1]["reason"] = "Action was pre-approved by the DBA"
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("altered after signing" in p for p in result.problems)


def test_deleted_record_is_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    del data["records"][1]
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("seq" in p for p in result.problems)


def test_inserted_record_is_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    forged = dict(data["records"][0])
    forged["seq"] = 1
    forged["action"] = "db.drop_everything"
    data["records"].insert(1, forged)
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok


def test_reordered_records_are_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    data["records"][1], data["records"][2] = data["records"][2], data["records"][1]
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("prev_hash" in p or "seq" in p for p in result.problems)


def test_swapped_decision_is_detected(populated_chain, tmp_path):
    """The most dangerous tamper: turning a DENY into an ALLOW."""
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    data["records"][1]["decision"] = "ALLOW"
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("altered after signing" in p for p in result.problems)


def test_signature_from_another_key_is_rejected(populated_chain, tmp_path, keypair):
    from agentproof.core.chain import generate_keypair

    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    other_private, _ = generate_keypair()
    other_chain = Chain(other_private, subject="attacker")
    forged = other_chain.append(
        actor="attacker",
        action="db.write",
        decision="ALLOW",
        reason="trust me",
        policy_id="pol-1",
        policy_digest="pd-1",
        inputs_digest="id-9",
    )

    data = _load_raw(path)
    data["records"][1]["signature"] = forged.signature
    data["records"][1]["record_hash"] = forged.record_hash
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("signature" in p.lower() for p in result.problems)


# ----------------------------------------------------------------------
# the seal
# ----------------------------------------------------------------------
def test_full_rewrite_is_caught_by_the_seal(populated_chain, tmp_path):
    """The case a hash chain alone cannot catch.

    Someone with the signing key rewrites every record and re-signs. The
    chain is internally consistent — but the seal no longer matches.
    """
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")
    original_seal = populated_chain.seal

    # Rebuild the chain from scratch with the same key, changing history.
    private = populated_chain._private_key
    rewritten = Chain(private, subject=populated_chain.subject, chain_id=populated_chain.chain_id)
    for receipt in populated_chain.receipts:
        rewritten.append(
            actor=receipt.actor,
            action=receipt.action,
            decision="ALLOW",  # every decision becomes permissive
            reason=receipt.reason,
            policy_id=receipt.policy_id,
            policy_digest=receipt.policy_digest,
            inputs_digest=receipt.inputs_digest,
        )
    rewritten.seal_chain()
    _write(rewritten, path)

    # The rewritten chain verifies internally...
    internal = verify_receipts(
        list(rewritten.receipts),
        rewritten.public_key,
        seal=rewritten.seal,
    )
    assert internal.ok, "a fully re-signed chain should be internally consistent"

    # ...but the original seal exposes it.
    result = verify_receipts(
        list(rewritten.receipts),
        rewritten.public_key,
        seal=original_seal,
    )
    assert not result.ok
    assert any("seal" in p.lower() for p in result.problems)


def test_modified_seal_is_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    data["seal"]["record_count"] = 99
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("seal" in p.lower() for p in result.problems)


# ----------------------------------------------------------------------
# replay protection
# ----------------------------------------------------------------------
def test_duplicate_nonce_is_detected(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    data = _load_raw(path)
    data["records"][2]["nonce"] = data["records"][1]["nonce"]
    _save_raw(data, path)

    result = verify_chain_file(path)

    assert not result.ok
    assert any("nonce" in p.lower() for p in result.problems)


def test_appending_to_a_sealed_chain_is_refused(populated_chain):
    from agentproof.core.chain import ChainError

    populated_chain.seal_chain()

    with pytest.raises(ChainError, match="sealed"):
        populated_chain.append(
            actor="agent",
            action="anything",
            decision="ALLOW",
            reason="after the seal",
            policy_id="pol-1",
            policy_digest="pd-1",
            inputs_digest="id-x",
        )


def test_duplicate_nonce_is_refused_at_append_time(chain):
    chain.append(
        actor="a",
        action="x",
        decision="ALLOW",
        reason="first",
        policy_id="p",
        policy_digest="pd",
        inputs_digest="i",
        nonce="fixed-nonce",
    )

    from agentproof.core.chain import ChainError

    with pytest.raises(ChainError, match="nonce"):
        chain.append(
            actor="a",
            action="y",
            decision="ALLOW",
            reason="replay",
            policy_id="p",
            policy_digest="pd",
            inputs_digest="i",
            nonce="fixed-nonce",
        )


# ----------------------------------------------------------------------
# round-trip
# ----------------------------------------------------------------------
def test_chain_survives_save_and_load(populated_chain, tmp_path):
    populated_chain.seal_chain()
    path = _write(populated_chain, tmp_path / "chain.json")

    reloaded = Chain.load(path, populated_chain._private_key)

    assert len(reloaded) == len(populated_chain)
    assert reloaded.chain_id == populated_chain.chain_id
    assert reloaded.seal is not None
    assert reloaded.seal.seal_hash == populated_chain.seal.seal_hash
    for original, restored in zip(populated_chain.receipts, reloaded.receipts):
        assert original.record_hash == restored.record_hash

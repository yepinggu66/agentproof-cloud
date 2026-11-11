"""Robustness regressions for the product's core promises.

Each test here corresponds to a finding in ``output/agentproof-audit-core.md``
that was rated P0/P1 (see also ``output/agentproof-fix-D.md``):

* C-01 — verification must use the key the caller supplies, not the key the
  (possibly forged) chain file carries.
* C-02 — a concurrent read-modify-write append must fail loudly instead of
  silently dropping the other writer's signed decision.
* C-03 — an empty capability list must not turn the gate into default-allow.
* A-01 — Windows-encoded chain/policy files must read or fail with a domain
  error, never a raw ``UnicodeDecodeError``.
* C-04/C-05/C-06 — malformed authoring input fails as a decision or a failed
  verification result, not as an unhandled exception, and Markdown tables stay
  well-formed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from agentproof.core.chain import Chain, ChainError, generate_keypair
from agentproof.core.policy import PolicyError, load_policy
from agentproof.core.receipt import Decision
from agentproof.core.verify import verify_chain_file
from agentproof.evidence import build_aibom, build_evidence_pack
from agentproof.evidence.aibom import render_aibom_markdown
from agentproof.evidence.article26 import render_markdown


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _append(chain: Chain, action: str = "kb.search", decision: str = "ALLOW"):
    return chain.append(
        actor="agent",
        action=action,
        decision=decision,
        reason="r",
        policy_id="pol-1",
        policy_digest="pd-1",
        inputs_digest="id-1",
    )


def _public_hex(key) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _write_hex_key(path: Path, private) -> Path:
    path.write_text(_public_hex(private) + "\n", encoding="utf-8")
    return path


def _write_pem_key(path: Path, private) -> Path:
    path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return path


def _forged_chain(path: Path) -> tuple[Chain, object]:
    """A chain signed by an attacker key, used as the untrusted artifact."""
    attacker_private, _ = generate_keypair()
    chain = Chain(attacker_private, subject="forged")
    _append(chain, action="db.drop_all")
    chain.save(path)
    return chain, attacker_private


def _write_policy(tmp_path: Path, data: dict) -> Path:
    import yaml

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# ----------------------------------------------------------------------
# C-01: key_path is the trust anchor, and it really is used
# ----------------------------------------------------------------------
def test_key_path_overrides_the_embedded_key(tmp_path):
    """A forged chain must FAIL when checked against the trusted key."""
    forged_path = tmp_path / "forged.json"
    _, _ = _forged_chain(forged_path)
    trusted_private, _ = generate_keypair()

    hex_key = _write_hex_key(tmp_path / "trusted.hex", trusted_private)
    pem_key = _write_pem_key(tmp_path / "trusted.pub", trusted_private)
    trusted_public = trusted_private.public_key()

    for result in (
        verify_chain_file(forged_path, key_path=hex_key),
        verify_chain_file(forged_path, key_path=pem_key),
        verify_chain_file(forged_path, public_key=trusted_public),
    ):
        assert not result.ok
        assert any("signature does not verify" in p for p in result.problems)


def test_genuine_chain_passes_with_hex_and_pem_key_path(tmp_path):
    private, _ = generate_keypair()
    chain = Chain(private, subject="genuine")
    _append(chain)
    chain.seal_chain()
    path = chain.save(tmp_path / "chain.json")

    by_hex = verify_chain_file(path, key_path=_write_hex_key(tmp_path / "k.hex", private))
    by_pem = verify_chain_file(path, key_path=_write_pem_key(tmp_path / "k.pub", private))
    by_arg = verify_chain_file(path, public_key=private.public_key())
    embedded = verify_chain_file(path)

    for result in (by_hex, by_pem, by_arg, embedded):
        assert result.ok, result.problems
        assert result.seal_matches is True


def test_key_path_and_public_key_disagreeing_is_a_usage_error(tmp_path):
    forged_path = tmp_path / "forged.json"
    _, attacker_private = _forged_chain(forged_path)
    trusted_private, _ = generate_keypair()
    hex_key = _write_hex_key(tmp_path / "trusted.hex", trusted_private)

    with pytest.raises(ValueError, match="different keys"):
        verify_chain_file(
            forged_path,
            attacker_private.public_key(),
            key_path=hex_key,
        )

    # The same key supplied twice is not a conflict.
    result = verify_chain_file(
        forged_path,
        trusted_private.public_key(),
        key_path=hex_key,
    )
    assert not result.ok


def test_mismatch_between_supplied_and_embedded_key_is_warned_about(tmp_path):
    forged_path = tmp_path / "forged.json"
    _forged_chain(forged_path)
    trusted_private, _ = generate_keypair()

    result = verify_chain_file(
        forged_path, key_path=_write_hex_key(tmp_path / "t.hex", trusted_private)
    )

    assert not result.ok
    assert any("embedded in the chain file differs" in w for w in result.warnings)


def test_key_path_must_exist_and_be_usable(tmp_path):
    _, attacker_private = _forged_chain(tmp_path / "forged.json")
    junk = tmp_path / "junk.pub"
    junk.write_text("not a key", encoding="utf-8")

    with pytest.raises(ValueError, match="neither a PEM public key nor a hex"):
        verify_chain_file(tmp_path / "forged.json", key_path=junk)


def test_unreadable_embedded_key_is_ignored_when_a_trusted_key_is_supplied(tmp_path):
    private, _ = generate_keypair()
    chain = Chain(private, subject="s")
    _append(chain)
    path = chain.save(tmp_path / "chain.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["public_key"] = "zzz"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = verify_chain_file(path, public_key=private.public_key())

    assert result.ok, result.problems
    assert any("unreadable 'public_key' field" in w for w in result.warnings)

    # With no trusted key to fall back on, the corrupt field is a hard error.
    with pytest.raises(ValueError, match="unreadable 'public_key' field"):
        verify_chain_file(path)


# ----------------------------------------------------------------------
# C-03: empty capabilities must not fail open
# ----------------------------------------------------------------------
def test_empty_capability_list_denies_undeclared_action(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "version": 1,
            "subject": "s",
            "capabilities": [],
            "rules": [{"id": "allow-all", "action": "*", "effect": "allow"}],
        },
    )
    policy = load_policy(path)

    evaluation = policy.evaluate("db.drop_all")

    assert evaluation.decision is Decision.DENY
    assert not evaluation.permitted
    assert evaluation.conditions_checked == {"capability_declared": False}
    assert "never declared" in evaluation.reason


def test_missing_capability_list_denies_undeclared_action(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "version": 1,
            "subject": "s",
            "rules": [{"id": "allow-all", "action": "*", "effect": "allow"}],
        },
    )
    assert load_policy(path).evaluate("db.drop_all").decision is Decision.DENY


def test_declared_capability_still_allows_and_records_the_check(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "version": 1,
            "subject": "s",
            "capabilities": [{"name": "kb.search"}],
            "rules": [{"id": "allow-kb", "action": "kb.search", "effect": "allow"}],
        },
    )
    evaluation = load_policy(path).evaluate("kb.search")

    assert evaluation.decision is Decision.ALLOW
    assert evaluation.conditions_checked["capability_declared"] is True


def test_deny_and_halt_rules_are_unaffected_by_the_capability_check(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "version": 1,
            "subject": "s",
            "capabilities": [],
            "rules": [
                {"id": "deny-write", "action": "db.write", "effect": "deny"},
                {"id": "halt-review", "action": "order.refund", "effect": "halt"},
            ],
        },
    )
    policy = load_policy(path)

    assert policy.evaluate("db.write").decision is Decision.DENY
    assert policy.evaluate("order.refund").decision is Decision.HALT


# ----------------------------------------------------------------------
# C-02: concurrent read-modify-write append is detected
# ----------------------------------------------------------------------
def test_concurrent_append_is_detected_and_original_record_survives(tmp_path):
    private, _ = generate_keypair()
    path = Chain(private, subject="concurrent").save(tmp_path / "chain.json")

    first = Chain.load(path, private)
    second = Chain.load(path, private)

    first.append(
        actor="agent-A",
        action="a.act",
        decision="ALLOW",
        reason="r",
        policy_id="p",
        policy_digest="d",
        inputs_digest="i",
    )
    first.save(path)

    second.append(
        actor="agent-B",
        action="b.act",
        decision="DENY",
        reason="r",
        policy_id="p",
        policy_digest="d",
        inputs_digest="i",
    )
    with pytest.raises(ChainError, match="modified by another process"):
        second.save(path)

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert [record["action"] for record in on_disk["records"]] == ["a.act"]
    result = verify_chain_file(path)
    assert result.ok
    assert result.records_checked == 1


def test_deleted_chain_is_not_silently_recreated(tmp_path):
    private, _ = generate_keypair()
    path = Chain(private, subject="s").save(tmp_path / "chain.json")
    loaded = Chain.load(path, private)
    path.unlink()

    with pytest.raises(ChainError, match="deleted since it was loaded"):
        loaded.save(path)


def test_saving_the_same_chain_twice_is_allowed(tmp_path):
    private, _ = generate_keypair()
    chain = Chain(private, subject="s")
    _append(chain)
    path = chain.save(tmp_path / "chain.json")

    reloaded = Chain.load(path, private)
    _append(reloaded, action="second")
    reloaded.save(path)
    assert verify_chain_file(path).records_checked == 2

    _append(reloaded, action="third")
    reloaded.save(path)
    assert verify_chain_file(path).records_checked == 3


def test_save_is_atomic_and_leaves_no_temporary_file(tmp_path, monkeypatch):
    private, _ = generate_keypair()
    chain = Chain(private, subject="s")
    _append(chain)
    path = chain.save(tmp_path / "chain.json")
    original_bytes = path.read_bytes()

    def _crash(*args, **kwargs):
        raise OSError("simulated crash mid-save")

    monkeypatch.setattr("agentproof.core.chain.os.replace", _crash)
    _append(chain, action="second")
    with pytest.raises(OSError, match="simulated crash"):
        chain.save(path)

    # The previous evidence file is untouched and no temp file is left behind.
    assert path.read_bytes() == original_bytes
    assert sorted(p.name for p in tmp_path.iterdir()) == ["chain.json"]
    monkeypatch.undo()
    chain.save(path)  # and the chain can still be saved once the crash is gone
    assert verify_chain_file(path).records_checked == 2


def test_read_only_chain_from_records_can_still_be_saved(tmp_path):
    """``Chain.from_records`` builds via ``__new__``; save() must not blow up."""
    private, _ = generate_keypair()
    source = Chain(private, subject="s")
    _append(source)
    read_only = Chain.from_records(list(source.receipts), private.public_key())
    assert read_only._private_key is None

    path = read_only.save(tmp_path / "copy.json")

    assert verify_chain_file(path).ok


# ----------------------------------------------------------------------
# A-01: Windows encodings must read or fail with a domain error
# ----------------------------------------------------------------------
_GOOD_POLICY = (
    "version: 1\n"
    "subject: s\n"
    "capabilities:\n"
    "  - name: kb.search\n"
    "rules:\n"
    "  - id: allow-kb\n"
    "    action: kb.search\n"
    "    effect: allow\n"
    "    reason: 只读知识库访问已预先批准\n"
)


def test_policy_with_utf8_bom_loads(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + _GOOD_POLICY.encode("utf-8"))

    assert load_policy(path).evaluate("kb.search").decision is Decision.ALLOW


def test_policy_in_utf16_loads(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_bytes(_GOOD_POLICY.encode("utf-16"))

    assert load_policy(path).evaluate("kb.search").decision is Decision.ALLOW


def test_policy_in_gbk_raises_policy_error_not_unicode_error(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_bytes(_GOOD_POLICY.encode("gbk"))

    with pytest.raises(PolicyError, match="Re-save it as UTF-8"):
        load_policy(path)


def _saved_chain_text(tmp_path: Path) -> tuple[Path, str]:
    private, _ = generate_keypair()
    chain = Chain(private, subject="s")
    chain.append(
        actor="agent",
        action="kb.search",
        decision="ALLOW",
        reason="理由",
        policy_id="p",
        policy_digest="d",
        inputs_digest="i",
    )
    path = chain.save(tmp_path / "chain.json")
    return path, path.read_text(encoding="utf-8")


def test_chain_with_utf8_bom_verifies(tmp_path):
    path, text = _saved_chain_text(tmp_path)
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))

    assert verify_chain_file(path).ok


def test_chain_in_utf16_verifies_and_loads(tmp_path):
    path, text = _saved_chain_text(tmp_path)
    path.write_bytes(text.encode("utf-16"))

    result = verify_chain_file(path)
    assert result.ok, result.problems

    private, _ = generate_keypair()
    # Loading needs the matching key only for future appends; the records and
    # their hashes must survive the encoding round-trip either way.
    loaded = Chain.load(path, private)
    assert len(loaded) == 1


def test_chain_in_gbk_raises_domain_errors_not_unicode_errors(tmp_path):
    path, text = _saved_chain_text(tmp_path)
    path.write_bytes(text.encode("gbk"))

    with pytest.raises(ValueError, match="Re-save it as UTF-8"):
        verify_chain_file(path)

    private, _ = generate_keypair()
    with pytest.raises(ChainError, match="Re-save it as UTF-8"):
        Chain.load(path, private)


# ----------------------------------------------------------------------
# C-04: malformed conditions HALT rather than raise
# ----------------------------------------------------------------------
def test_non_integer_max_input_bytes_halts(tmp_path):
    path = _write_policy(
        tmp_path,
        {
            "version": 1,
            "subject": "s",
            "capabilities": [{"name": "kb.search"}],
            "rules": [
                {
                    "id": "allow-kb",
                    "action": "kb.search",
                    "effect": "allow",
                    "conditions": {"max_input_bytes": "64 KiB"},
                }
            ],
        },
    )
    policy = load_policy(path)

    evaluation = policy.evaluate("kb.search", inputs={"q": "x"})

    assert evaluation.decision is Decision.HALT
    assert not evaluation.permitted
    assert "cannot be evaluated" in evaluation.reason


# ----------------------------------------------------------------------
# C-05: corrupt chain documents produce a failed result, not a crash
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        {"records": [7]},
        {"records": 7},
        {"records": [{"seq": 0}]},
        {"records": [], "seal": "x"},
    ],
)
def test_corrupt_chain_document_returns_failed_verification(tmp_path, payload):
    private, _ = generate_keypair()
    path = tmp_path / "corrupt.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = verify_chain_file(path, public_key=private.public_key())

    assert not result.ok
    assert any("malformed chain document" in p for p in result.problems)


# ----------------------------------------------------------------------
# C-06: pipes in evidence tables must not break the row
# ----------------------------------------------------------------------
def test_markdown_tables_escape_pipes_in_actor_and_action(tmp_path):
    private, _ = generate_keypair()
    chain = Chain(private, subject="s")
    chain.append(
        actor="agent|evil",
        action="db.write|x",
        decision="DENY",
        reason="bad",
        policy_id="p",
        policy_digest="d",
        inputs_digest="i",
    )

    markdown = render_markdown(build_evidence_pack(chain))
    row = next(
        line
        for line in markdown.splitlines()
        if line.startswith("| ") and "db.write" in line
    )
    assert "agent\\|evil" in row
    assert "db.write\\|x" in row
    assert row.count(" | ") == 5  # exactly the six cells of the header


def test_aibom_tables_escape_pipes(tmp_path):
    from agentproof.capture.events import AgentEvent, EventKind

    events = [
        AgentEvent(
            kind=EventKind.TOOL_CALL,
            ts="2026-01-01T00:00:00Z",
            agent="agent|evil",
            action="tool|name",
            inputs={},
        )
    ]
    aibom = build_aibom(events)
    markdown = render_aibom_markdown(aibom)

    assert "agent\\|evil" in markdown
    assert "tool\\|name" in markdown

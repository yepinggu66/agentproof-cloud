"""The dashboard's browser-side verifier must stay correct.

The HTML dashboard contains a hand-written SHA-256 and a re-implementation of
the canonical JSON format. If either drifts from the Python implementation,
the page would show a green check that means nothing — which is worse than
no check at all.

These tests run the embedded JavaScript under Node and compare it against the
Python implementation and against Node's own crypto module.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agentproof.core.canonical import canonical_bytes
from agentproof.core.receipt import Receipt
from agentproof.dashboard import build_dashboard_data, render_dashboard
from agentproof.dashboard_js import JS_VERIFIER

node = shutil.which("node")
requires_node = pytest.mark.skipif(node is None, reason="node is not installed")


@pytest.fixture
def chain_data(populated_chain):
    populated_chain.seal_chain()
    return populated_chain.to_dict()


@pytest.fixture
def verifier_module(tmp_path, chain_data):
    """Load the embedded JavaScript under Node and expose its functions."""
    if node is None:
        pytest.skip("node is not installed")

    script = tmp_path / "load.mjs"
    script.write_text(
        """
import fs from 'fs';
const src = fs.readFileSync(process.argv[2], 'utf8');
const mod = new Function(src + `
  return { verifyChain, canonicalJson, sha256Hex, b64Encode };
`)();
console.log(JSON.stringify({
  sha256Hex: mod.sha256Hex('abc'),
  canonical: mod.canonicalJson({b: 1, a: [1, 2], c: '中文'}),
  b64: mod.b64Encode('hello'),
}));
""",
        encoding="utf-8",
    )

    js_path = tmp_path / "verifier.js"
    js_path.write_text(JS_VERIFIER, encoding="utf-8")

    result = subprocess.run(
        [node, str(script), str(js_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# ----------------------------------------------------------------------
# SHA-256 correctness
# ----------------------------------------------------------------------
@requires_node
def test_sha256_matches_node_crypto(tmp_path, chain_data):
    """The hand-written SHA-256 must agree with a known-good implementation."""
    import hashlib

    samples = [
        "",
        "abc",
        "hello world",
        "a" * 1000,
        "中文测试",
        '{"a":1}',
        "x" * 55,
        "y" * 56,
        "z" * 64,
        "z" * 1000,
        "emoji 🚀 test",
    ]

    script = tmp_path / "sha.mjs"
    script.write_text(
        """
import fs from 'fs';
const src = fs.readFileSync(process.argv[2], 'utf8');
const mod = new Function(src + 'return { sha256Hex };')();
const inputs = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
console.log(JSON.stringify(inputs.map((s) => mod.sha256Hex(s))));
""",
        encoding="utf-8",
    )
    js_path = tmp_path / "verifier.js"
    js_path.write_text(JS_VERIFIER, encoding="utf-8")
    samples_path = tmp_path / "samples.json"
    samples_path.write_text(json.dumps(samples), encoding="utf-8")

    result = subprocess.run(
        [node, str(script), str(js_path), str(samples_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    computed = json.loads(result.stdout)

    for sample, digest in zip(samples, computed):
        expected = hashlib.sha256(sample.encode("utf-8")).hexdigest()
        assert digest == expected, f"mismatch for {sample[:20]!r}"


@requires_node
def test_canonical_matches_python(verifier_module, chain_data):
    """Two independent implementations must produce identical bytes."""
    payload = build_dashboard_data(chain_data)

    for record in payload["records"]:
        receipt = Receipt.from_dict(record)
        expected = base64.b64encode(canonical_bytes(receipt.body())).decode("ascii")
        assert record["canonical_b64"] == expected


@requires_node
def test_browser_verification_passes_on_a_good_chain(tmp_path, chain_data):
    payload = build_dashboard_data(chain_data)

    script = tmp_path / "verify.mjs"
    script.write_text(
        """
import fs from 'fs';
const src = fs.readFileSync(process.argv[2], 'utf8');
const mod = new Function(src + 'return { verifyChain };')();
const data = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
console.log(JSON.stringify(mod.verifyChain(data)));
""",
        encoding="utf-8",
    )
    js_path = tmp_path / "verifier.js"
    js_path.write_text(JS_VERIFIER, encoding="utf-8")
    data_path = tmp_path / "data.json"
    data_path.write_text(json.dumps(payload), encoding="utf-8")

    result = subprocess.run(
        [node, str(script), str(js_path), str(data_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout)

    assert outcome["ok"] is True
    assert outcome["problems"] == []
    assert outcome["records"] == 3
    assert outcome["seal"] == "matches"


# ----------------------------------------------------------------------
# the rendered document
# ----------------------------------------------------------------------
def test_dashboard_is_self_contained(chain_data):
    html = render_dashboard(chain_data, subject="acme")
    assert "<script" in html
    # No external scripts, stylesheets, fonts, or network calls.
    assert "src=\"http" not in html
    assert "href=\"http" not in html
    assert "@import" not in html
    assert "fetch(" not in html
    assert "XMLHttpRequest" not in html


def test_dashboard_embeds_the_data(chain_data):
    html = render_dashboard(chain_data, subject="acme")
    assert 'id="payload"' in html
    assert "kb.search" in html
    assert chain_data["chain_id"] in html


def test_dashboard_shows_the_verdict(chain_data):
    from agentproof.core.chain import Seal
    from agentproof.core.verify import load_public_key_hex, verify_receipts

    receipts = [Receipt.from_dict(r) for r in chain_data["records"]]
    verification = verify_receipts(
        receipts,
        load_public_key_hex(chain_data["public_key"]),
        seal=Seal.from_dict(chain_data["seal"]),
    )

    html = render_dashboard(
        chain_data,
        subject="acme",
        verification=verification.to_dict(),
        limitations=["not a legal opinion"],
        control_map={"eu-ai-act-article-26": ["26(1)"]},
    )
    assert "Integrity verified" in html
    assert "not a legal opinion" in html
    assert "26(1)" in html


def test_dashboard_shows_failure_state(chain_data):
    from agentproof.core.chain import Seal
    from agentproof.core.verify import load_public_key_hex, verify_receipts

    receipts = [Receipt.from_dict(r) for r in chain_data["records"]]
    tampered = {**chain_data["records"][1], "decision": "ALLOW"}
    receipts[1] = Receipt.from_dict(tampered)

    verification = verify_receipts(
        receipts,
        load_public_key_hex(chain_data["public_key"]),
        seal=Seal.from_dict(chain_data["seal"]),
    )

    html = render_dashboard(
        chain_data, subject="acme", verification=verification.to_dict()
    )
    assert "Integrity check failed" in html
    assert "verdict fail" in html


def test_dashboard_escapes_html_in_reasons(chain_data):
    """A reason containing markup must not break the document or inject code."""
    import copy

    tampered = copy.deepcopy(chain_data)
    tampered["records"][0]["reason"] = "<script>alert('x')</script>"
    html = render_dashboard(tampered, subject="acme")

    # The visible table renders the reason as escaped text.
    assert "&lt;script&gt;alert" in html

    # Inside the embedded JSON payload, every "<" is written as < so the
    # HTML parser can never be tricked into ending the script element early.
    payload_region = html.split('type="application/json">')[1].split("</script>")[0]
    assert "<" not in payload_region
    assert "\\u003cscript" in payload_region


def test_dashboard_payload_survives_json_round_trip(chain_data):
    """The embedded payload must parse back to exactly the original data."""
    import html as html_module
    import re

    payload = build_dashboard_data(chain_data)
    html = render_dashboard(chain_data, subject="acme")
    match = re.search(
        r'<script id="payload" type="application/json">(.*?)</script>', html, re.S
    )
    assert match
    parsed = json.loads(match.group(1))
    assert parsed["chain_id"] == payload["chain_id"]
    assert len(parsed["records"]) == len(payload["records"])
    assert parsed["records"][0]["canonical_b64"] == payload["records"][0]["canonical_b64"]


def test_dashboard_handles_a_chain_with_no_records():
    html = render_dashboard(
        {"chain_id": "empty", "subject": "s", "public_key": "00" * 32, "records": []},
        subject="s",
    )
    assert "empty" in html
    assert "决策总数" in html

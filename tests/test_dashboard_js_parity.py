"""Byte-level parity: the dashboard's JavaScript canonicalizer vs Python's.

RT-02 regression test. The dashboard recomputes the canonical JSON of every
receipt inside the browser and compares the bytes with what the Python side
hashed. If the two implementations disagree on *any* input the Python side can
produce, an intact chain is reported as tampered — a false accusation, which is
the worst failure mode for audit evidence.

The old implementation rebuilt the canonical value as a plain JS object and
called ``JSON.stringify`` on it. JS engines enumerate "integer index" keys
(``"2"``, ``"10"``) in numeric order no matter how the object was built, so
``context`` keys that look like indexes came out as ``{"2":...,"10":...}``
instead of Python's code-point order ``{"10":...,"2":...}``. Astral-plane keys
had the same problem in the other direction: JS compares UTF-16 code units,
Python compares code points.

These tests load the embedded verifier under real Node and compare raw bytes.
They are skipped when Node is not installed.

Run: ``python -m pytest -q -p no:cacheprovider tests/test_dashboard_js_parity.py``
"""

from __future__ import annotations

import json
import math
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from agentproof.core.canonical import canonical_bytes, canonical_json
from agentproof.dashboard import build_dashboard_data
from agentproof.dashboard_js import JS_VERIFIER

node = shutil.which("node")
requires_node = pytest.mark.skipif(node is None, reason="node is not installed")

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Node harness. It loads the verifier exactly the way the browser (and the
#: existing dashboard tests) do and writes results to a file, so the result
#: never depends on the host console encoding.
_LOADER = """
import fs from 'node:fs';
const src = fs.readFileSync(process.argv[2], 'utf8');
const mod = new Function(src + '\\nreturn { canonicalJson, verifyChain };')();
const mode = process.argv[3];
const payload = fs.readFileSync(process.argv[4], 'utf8');
const outPath = process.argv[5];
if (mode === 'canonical') {
  const texts = JSON.parse(payload);
  fs.writeFileSync(outPath, JSON.stringify(texts.map((t) => mod.canonicalJson(JSON.parse(t)))), 'utf8');
} else if (mode === 'verify') {
  fs.writeFileSync(outPath, JSON.stringify(mod.verifyChain(JSON.parse(payload))), 'utf8');
} else {
  throw new Error('unknown mode: ' + mode);
}
"""


@pytest.fixture(scope="module")
def js_harness(tmp_path_factory):
    """A callable ``run(mode, payload)`` that executes the embedded verifier."""
    if node is None:
        pytest.skip("node is not installed")

    root = tmp_path_factory.mktemp("dashboard_js_parity")
    loader = root / "loader.mjs"
    loader.write_text(_LOADER, encoding="utf-8")
    verifier = root / "verifier.js"
    verifier.write_text(JS_VERIFIER, encoding="utf-8")

    calls = {"n": 0}

    def run(mode: str, payload: object) -> object:
        calls["n"] += 1
        tag = f"{mode}-{calls['n']}"
        in_path = root / f"in-{tag}.json"
        out_path = root / f"out-{tag}.json"
        in_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        result = subprocess.run(
            [node, str(loader), str(verifier), mode, str(in_path), str(out_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(out_path.read_text(encoding="utf-8"))

    return run


def _canonical_parity(run, values: list[object]) -> None:
    """Feed the same JSON text to both implementations, compare raw bytes."""
    texts = [json.dumps(value, ensure_ascii=False) for value in values]
    js_results = run("canonical", texts)
    assert len(js_results) == len(texts)

    mismatches = []
    for text, js_out in zip(texts, js_results):
        py_bytes = canonical_bytes(json.loads(text))
        js_bytes = js_out.encode("utf-8")
        if py_bytes != js_bytes:
            mismatches.append((text, py_bytes, js_bytes))
    assert not mismatches, "\n".join(
        f"input: {text}\n  python bytes: {py_bytes!r}\n  js bytes    : {js_bytes!r}"
        for text, py_bytes, js_bytes in mismatches
    )


# ----------------------------------------------------------------------
# Canonicalization: key ordering
# ----------------------------------------------------------------------
@requires_node
def test_numeric_string_keys_sort_by_code_point(js_harness):
    """RT-02: ``"10"`` sorts before ``"2"`` in Python; JS objects reorder them."""
    value = {"2": "two", "10": "ten"}
    expected = '{"10":"ten","2":"two"}'
    assert canonical_json(value) == expected
    js_out = js_harness("canonical", [json.dumps(value)])[0]
    assert js_out == expected
    # The acceptance criterion: the exact bytes Python would have hashed.
    assert js_out.encode("utf-8") == canonical_bytes(value)


@requires_node
def test_numeric_keys_mixed_with_alphabetic_keys(js_harness):
    value = {"10": "a", "2": "b", "a": "c", "1": "d", "01": "z"}
    expected = '{"01":"z","1":"d","10":"a","2":"b","a":"c"}'
    assert canonical_json(value) == expected
    js_out = js_harness("canonical", [json.dumps(value)])[0]
    assert js_out == expected
    assert js_out.encode("utf-8") == canonical_bytes(value)


@requires_node
def test_numeric_looking_keys_that_are_not_integer_indexes(js_harness):
    """Only "integer index" keys get reordered by JS; mixed numeric-looking
    keys ("1.5", "-1", "1e3") must still sort by code point like Python."""
    values = [
        {"1.5": "a", "1e3": "b", "-1": "c", "2": "d", "a": "e"},
        {"0": 1, "00": 2, "0.0": 3, " 0": 4},
    ]
    _canonical_parity(js_harness, values)


@requires_node
def test_numeric_keys_nested_inside_arrays_and_objects(js_harness):
    value = {"rows": [{"2": {"id": "r2"}, "10": {"id": "r10"}}], "3": []}
    _canonical_parity(js_harness, [value])


@requires_node
def test_astral_plane_keys_sort_by_code_point(js_harness):
    """Emoji (U+10000+) sort after the whole BMP in Python, but their UTF-16
    surrogates sort before U+E000..U+FFFF, which is where JS ``<`` disagrees."""
    value = {"\uE000": "private-use", "\U0001F600": "grin", "\uFFFF": "bmp-end"}
    expected = '{"\ue000":"private-use","\uffff":"bmp-end","\U0001F600":"grin"}'
    assert canonical_json(value) == expected
    js_out = js_harness("canonical", [json.dumps(value, ensure_ascii=False)])[0]
    assert js_out == expected
    assert js_out.encode("utf-8") == canonical_bytes(value)


@requires_node
def test_astral_boundary_and_prefix_keys(js_harness):
    values = [
        {"\U00010000": "astral", "\uFFFF": "bmp"},
        {"a": 1, "ab": 2, "abc": 3, "": 4},
        {"caf\u00e9": 1, "cafe\u0301": 2},  # NFC vs NFD: no normalization either side
    ]
    _canonical_parity(js_harness, values)


# ----------------------------------------------------------------------
# Canonicalization: values, escaping, nesting, numbers
# ----------------------------------------------------------------------
@requires_node
def test_escaping_parity(js_harness):
    values = [
        {"q": 'he said "hi"', "b": "back\\slash", "tab": "a\tb", "nl": "a\nb"},
        {"cr": "a\rb", "ff": "a\fb", "bs": "a\bb", "slash": "a/b"},
        {"c0": "\u0000", "c1": "\u0001", "c1f": "\u001f", "del": "\u007f", "c1x": "\u0080"},
        {'a"b': 1, "c\\d": 2, "e\tf": 3},  # escaped characters in *keys*
        {"cn": "\u4e2d\u6587", "accent": "caf\u00e9", "nfd": "cafe\u0301"},
    ]
    _canonical_parity(js_harness, values)


@requires_node
def test_nesting_and_empty_containers(js_harness):
    values = [
        {"a": {"b": [{"z": 1, "2": 2}, [], {}]}, "10": None, "2": True},
        {},
        [],
        [{}, [], {"x": {}}],
        [None, True, False, 0, "", "x"],
        {"a": None, "b": [None]},
        "😀",
        {"emoji": "a\U0001F600b", "10": "\U0001F680", "2": "\u00e9"},
    ]
    _canonical_parity(js_harness, values)


@requires_node
def test_number_parity(js_harness):
    values = [
        [0, 1, -1, 7, 42, -13, 2**31, 9007199254740991],
        [0.1, 1.5, -2.25, 3.141592653589793, 1.1 + 2.2],
        # Python repr(float) uses exponent notation below 1e-4 with a sign and
        # at least two exponent digits; JS Number#toString does not.
        [1e-7, 1.23e-5, 1e-4, 2.5e-16, 4.9e-324],
        [0.0001, 0.000123, 123.456, 4503599627370495.5],
        {"2": 1.5, "10": 2, "a": 1e-7, "b": [1, 2.5]},
    ]
    _canonical_parity(js_harness, values)


@requires_node
def test_negative_zero_parity(js_harness):
    """``-0.0`` must canonicalize as ``-0.0`` (Python repr), not ``0``.

    ``JSON.parse("-0.0")`` gives JS ``-0``, which ``% 1 === 0`` would route
    through the integer branch and serialize as ``"0"``; that used to flip an
    intact chain containing a negative-zero float into a false tamper report."""
    assert canonical_bytes(-0.0) == b"-0.0"
    assert canonical_json(-0.0) == "-0.0"
    assert canonical_json(json.loads("-0.0")) == "-0.0"
    for value in [-0.0, {"z": -0.0}, {"v": [-0.0, 0]}]:
        text = json.dumps(value)
        js_out = js_harness("canonical", [text])[0]
        assert js_out.encode("utf-8") == canonical_bytes(json.loads(text))
    assert js_harness("canonical", ["-0.0"])[0] == "-0.0"


@requires_node
def test_random_non_integral_floats_parity(js_harness):
    """Fuzz shortest-round-trip formatting across the double exponent range.

    Only non-integral values are compared: JSON.parse cannot distinguish a
    whole-number float from an int, so a JS verifier fed parsed JSON cannot
    reproduce Python's ``1.0`` (that limitation predates and is orthogonal to
    RT-02; receipts carry ints and non-integral floats in practice)."""
    rng = random.Random(20261030)
    values: list[float] = []
    while len(values) < 250:
        candidate = math.ldexp(rng.random(), rng.randint(-320, 320))
        if candidate == 0 or math.isinf(candidate) or float(candidate).is_integer():
            continue
        values.append(candidate)
    _canonical_parity(js_harness, values)


_KEY_POOL = [
    "2",
    "10",
    "1",
    "01",
    "0",
    "10.5",
    "-1",
    "a",
    "b",
    "é",
    "\U0001F600",
    "\uE000",
    "\uFFFF",
    "\tq",
    "",
    "中",
]
_STRING_POOL = [
    "",
    "plain",
    'quote " and \\ backslash',
    "tab\tnl\ncr\r",
    "\u0000\u0001\u001f\u007f",
    "中文字符",
    "café",
    "cafe\u0301",
    "\U0001F600\U0001F680",
    "\u2028\u2029",
]
_FLOAT_POOL = [0.1, -1.5, 1e-7, 3.25, 1e-4 + 1e-13, 12345.6789, -2.5e-16]


def _random_json(rng: random.Random, depth: int):
    kinds = ["null", "bool", "int", "float", "str", "list", "dict"]
    if depth <= 0:
        kinds = kinds[:5]
    kind = rng.choice(kinds)
    if kind == "null":
        return None
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "int":
        return rng.choice([0, 1, -1, 42, 2**31, 9007199254740991, -7])
    if kind == "float":
        return rng.choice(_FLOAT_POOL)
    if kind == "str":
        return rng.choice(_STRING_POOL)
    if kind == "list":
        return [_random_json(rng, depth - 1) for _ in range(rng.randint(0, 3))]
    keys = rng.sample(_KEY_POOL, rng.randint(0, 4))
    return {key: _random_json(rng, depth - 1) for key in keys}


@requires_node
def test_random_documents_parity(js_harness):
    """Structural fuzz: random nesting of numeric/emoji/escaped keys, strings,
    numbers and empty containers must canonicalize to identical bytes."""
    rng = random.Random(20261030)
    docs = [_random_json(rng, 4) for _ in range(80)]
    _canonical_parity(js_harness, docs)


# ----------------------------------------------------------------------
# The verifier itself: intact chains must PASS, tampered chains must FAIL
# ----------------------------------------------------------------------
@pytest.fixture
def numeric_key_chain():
    from agentproof.core.chain import Chain, generate_keypair

    private, _public = generate_keypair()
    chain = Chain(private, subject="parity")
    chain.append(
        actor="support-agent",
        action="order.refund",
        decision="ALLOW",
        reason="refund within the pre-approved limit",
        policy_id="acme-support-v3",
        policy_digest="pd-v3",
        inputs_digest="id-1",
        context={
            "2": "two",
            "10": "ten",
            "a": "alpha",
            "\uE000": "private-use",
            "\U0001F600": "grin",
            "nested": {"2": {"row": 1}, "10": {"row": 2}},
            "ratio": 0.125,
            "tiny": 1e-07,
        },
    )
    chain.append(
        actor="support-agent",
        action="db.write",
        decision="DENY",
        reason="not a declared capability",
        policy_id="acme-support-v3",
        policy_digest="pd-v3",
        inputs_digest="id-2",
        context={"10": "x", "2": "y"},
    )
    chain.seal_chain()
    return chain


@requires_node
def test_intact_sealed_chain_with_numeric_keys_verifies_in_page(js_harness, numeric_key_chain):
    """The regression: Python says PASS, so the page must too (no false positive)."""
    payload = build_dashboard_data(numeric_key_chain.to_dict())
    outcome = js_harness("verify", payload)
    assert outcome["ok"] is True, outcome["problems"]
    assert outcome["problems"] == []
    assert outcome["seal"] == "matches"
    assert outcome["records"] == 2


@requires_node
def test_intact_demo_chain_verifies_in_page(js_harness):
    demo = REPO_ROOT / "demo" / "chain.json"
    if not demo.exists():
        pytest.skip("demo/chain.json is not present")
    payload = build_dashboard_data(json.loads(demo.read_text(encoding="utf-8")))
    outcome = js_harness("verify", payload)
    assert outcome["ok"] is True, outcome["problems"]
    assert outcome["problems"] == []
    assert outcome["seal"] == "matches"


@requires_node
def test_tampering_is_still_detected(js_harness, numeric_key_chain):
    """The fix must not make the canonicalizer blind to real tampering."""
    payload = build_dashboard_data(numeric_key_chain.to_dict())
    payload["records"][0]["reason"] = "refund of any size, no questions asked"
    outcome = js_harness("verify", payload)
    assert outcome["ok"] is False
    assert any("recomputed hash does not match" in p for p in outcome["problems"])

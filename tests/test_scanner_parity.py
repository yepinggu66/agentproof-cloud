"""Browser scanner (site/assets/scanner.js) must agree with server/scan.py.

The offline preview is only honest if it reports the same findings as the
server. This test runs the real JavaScript through Node.js and compares
grades, finding ids, capabilities and the rendered policy.yaml byte for byte.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from server.scan import scan

NODE = shutil.which("node")
ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is required for JS/Python parity")

NODE_SCRIPT = """
const scanner = require('./site/assets/scanner.js');
const fs = require('fs');
const kind = process.argv[1];
const file = process.argv[2];
const result = scanner.scan(kind, fs.readFileSync(file, 'utf8'));
process.stdout.write(JSON.stringify({
  grade: result.grade,
  score: result.score,
  ids: result.findings.map((finding) => finding.id),
  caps: result.capabilities,
  policy: result.policy_yaml,
}));
"""


def _run_js(kind: str, path: str) -> dict:
    completed = subprocess.run(
        [NODE, "-e", NODE_SCRIPT, kind, path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        cwd=str(ROOT),
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@pytest.mark.parametrize(
    "kind,filename",
    [
        ("mcp", "tests/sample-dangerous-mcp.json"),
        ("mcp", "tests/sample-safe-mcp.json"),
        ("python", "tests/sample-python-agent.py"),
    ],
)
def test_javascript_matches_python(kind, filename):
    with open(filename, encoding="utf-8") as handle:
        content = handle.read()
    python_result = scan(kind, content)
    js_result = _run_js(kind, filename)

    assert js_result["grade"] == python_result.grade
    assert js_result["score"] == python_result.score
    assert sorted(js_result["ids"]) == sorted(finding.id for finding in python_result.findings)
    assert js_result["caps"] == python_result.capabilities
    assert js_result["policy"] == python_result.policy_yaml, "policy.yaml differs between implementations"

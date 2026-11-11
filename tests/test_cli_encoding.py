"""Encoding regressions: what goes in and what comes out of the CLI.

Three separate failures motivated this file, all of them invisible on a
developer machine with a UTF-8 locale and obvious in CI:

* **Output** (RT-03) — ``click.echo`` of a reason/action containing an emoji
  raised ``UnicodeEncodeError`` when stdout was redirected on Windows (the CI
  norm). The command died with exit 1, which ``agentproof verify`` reserves
  for "verification failed", and ``--json`` output was truncated.
* **Input** (RT-05) — a UTF-8 JSONL file with a BOM lost its first line while
  ``record`` still exited 0; a UTF-16 file produced a bare traceback and exit 1.
  ``read_trace`` had the same BOM blind spot.
* **Test harness** (RT-01) — ``subprocess.run(..., text=True)`` without an
  explicit ``encoding`` decodes Node's UTF-8 output with the ANSI code page.

A later CLI-layer handoff from the core fixes adds two more guarantees checked
here: chain files may arrive as UTF-8 with a BOM (or UTF-16 with a BOM) and
every command that reads one must accept that; and a chain file that cannot be
safely decoded, a concurrent ``chain-append`` race, or any other ``ChainError``
must end as a clean exit code with a message — never as a traceback.

The harness checks run real subprocesses so they exercise the actual stdio
layer rather than a mock of it.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agentproof.capture.events import AgentEvent, EventKind
from agentproof.capture.recorder import Recorder, iter_trace, read_trace

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SRC = REPO_ROOT / "src"

node = shutil.which("node")
requires_node = pytest.mark.skipif(node is None, reason="node is not installed")

POLICY_WITH_EMOJI = """\
version: 1
subject: acme-support-agent
capabilities:
  - name: kb.search
rules:
  - id: allow-kb
    action: kb.search
    effect: allow
    reason: "KB read is pre-approved 🚀"
  - id: deny-default
    action: "*"
    effect: deny
    reason: default deny
"""

CASE_WITH_EMOJI = """\
version: 1
name: notify-emoji
steps:
  - action: "notify 🚀"
    inputs: {}
    expect:
      decision: allow
      outputs:
        message: "🚀 sent"
assertions: []
"""


def _cli_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for a real CLI child process (repo ``src`` on PYTHONPATH)."""
    child_env = os.environ.copy()
    pythonpath = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = (
        str(SRC) + (os.pathsep + pythonpath if pythonpath else "")
    )
    child_env.pop("PYTHONIOENCODING", None)
    child_env.update(env or {})
    return child_env


def _run_cli(
    *args: str,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run the CLI as a real process so stdio encoding is the real one."""
    return subprocess.run(
        [sys.executable, "-m", "agentproof.cli", *args],
        cwd=str(cwd),
        env=_cli_env(env),
        capture_output=True,
        timeout=120,
    )


# ----------------------------------------------------------------------
# RT-01: the node test harness must always decode as UTF-8
# ----------------------------------------------------------------------
@requires_node
def test_node_harness_output_round_trips_as_utf8(tmp_path):
    """Node writes UTF-8; the harness must say so when it decodes."""
    script = tmp_path / "emit.mjs"
    script.write_text(
        "console.log(JSON.stringify({text: '中文 🚀 café'}));\n", encoding="utf-8"
    )

    result = subprocess.run(
        [node, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"text": "中文 🚀 café"}


def test_every_text_subprocess_run_in_the_suite_declares_utf8():
    """Guard the three RT-01 call sites (and any future one).

    ``text=True`` without ``encoding`` is a latent platform bug: on Windows the
    pipe is decoded with the ANSI code page, which silently corrupts Node's
    UTF-8 output. This static check keeps the whole suite honest without having
    to install Node.
    """
    offenders: list[str] = []
    text_calls = 0

    for path in sorted(TESTS_DIR.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "run"
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            ):
                continue
            keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
            text_kw = keywords.get("text")
            if not (
                isinstance(text_kw, ast.Constant) and text_kw.value is True
            ):
                continue
            text_calls += 1
            encoding_kw = keywords.get("encoding")
            if not (
                isinstance(encoding_kw, ast.Constant)
                and encoding_kw.value == "utf-8"
            ):
                offenders.append(f"{path.name}:{call.lineno}")

    # The three node harness calls live in test_dashboard.py.
    assert text_calls >= 3, "expected to find the node subprocess harness calls"
    assert not offenders, (
        "subprocess.run(text=True) must pass encoding='utf-8': "
        + ", ".join(offenders)
    )


# ----------------------------------------------------------------------
# RT-03: output that the terminal cannot encode must not fail the command
# ----------------------------------------------------------------------
def test_cli_emoji_output_survives_gbk_redirect(tmp_path):
    """A cp936/GBK stdout must not turn a successful run into exit 1."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_WITH_EMOJI, encoding="utf-8")

    result = _run_cli(
        "policy-check",
        str(policy),
        "-a",
        "kb.search",
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "gbk"},
    )

    assert result.returncode == 0, result.stderr
    assert b"UnicodeEncodeError" not in result.stderr
    assert b"Traceback" not in result.stderr

    output = result.stdout.decode("gbk")
    assert "ALLOW" in output
    # The emoji is escaped, not dropped: the reader can still tell what was
    # there, and the exit code keeps meaning "the decision was ALLOW".
    assert "\\U0001f680" in output


def test_cli_emoji_output_is_unchanged_on_a_utf8_stream(tmp_path):
    """On a UTF-8 stdout the terminal sees the real character."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_WITH_EMOJI, encoding="utf-8")

    result = _run_cli(
        "policy-check",
        str(policy),
        "-a",
        "kb.search",
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "utf-8"},
    )

    assert result.returncode == 0, result.stderr
    assert "🚀" in result.stdout.decode("utf-8")


def test_cli_json_output_does_not_crash_on_gbk_redirect(tmp_path):
    """The ``--json`` branches echo JSON with ``ensure_ascii=False``."""
    case = tmp_path / "case.yaml"
    case.write_text(CASE_WITH_EMOJI, encoding="utf-8")

    result = _run_cli(
        "replay",
        str(case),
        "--json",
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "gbk"},
    )

    assert result.returncode == 0, result.stderr
    assert b"UnicodeEncodeError" not in result.stderr
    output = result.stdout.decode("gbk")
    assert "notify" in output  # document was not truncated mid-stream
    assert "\\U0001f680" in output


# ----------------------------------------------------------------------
# RT-05: JSONL input encodings
# ----------------------------------------------------------------------
def _raw_events() -> str:
    return (
        json.dumps(
            {
                "type": "tool_call",
                "agent": "support-agent",
                "name": "kb.search",
                "input": {"q": "refund policy"},
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "tool_call",
                "agent": "support-agent",
                "name": "db.write",
                "input": {"q": "x"},
            }
        )
        + "\n"
    )


def test_record_accepts_a_utf8_bom(tmp_path):
    """RT-05: a BOM must not be mistaken for a malformed first line."""
    raw = tmp_path / "raw.jsonl"
    raw.write_bytes(b"\xef\xbb\xbf" + _raw_events().encode("utf-8"))
    trace = tmp_path / "trace.jsonl"

    result = _run_cli(
        "record",
        str(trace),
        "--input",
        str(raw),
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "utf-8"},
    )

    assert result.returncode == 0, result.stderr
    assert b"skipping malformed line" not in result.stderr
    assert len(trace.read_text(encoding="utf-8").splitlines()) == 2


def test_record_rejects_utf16_with_exit_two(tmp_path):
    """RT-05: a non-UTF-8 input is a usage error, not a traceback and not exit 1."""
    raw = tmp_path / "raw.jsonl"
    raw.write_bytes(_raw_events().encode("utf-16"))
    trace = tmp_path / "trace.jsonl"

    result = _run_cli(
        "record",
        str(trace),
        "--input",
        str(raw),
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "utf-8"},
    )

    assert result.returncode == 2
    assert b"Traceback" not in result.stderr
    stderr = result.stderr.decode("utf-8", "replace")
    assert "UTF-8" in stderr
    # Nothing was recorded, so there is no half-written trace to trust.
    assert not trace.exists()


def test_read_trace_accepts_a_utf8_bom(tmp_path):
    """RT-05: the trace reader, not just ``record``, must accept a BOM."""
    plain = tmp_path / "plain.jsonl"
    recorder = Recorder(plain)
    recorder.record_many(
        [
            AgentEvent(kind=EventKind.TOOL_CALL, ts="2026-10-30T00:00:00Z", action="kb.search"),
            AgentEvent(kind=EventKind.NOTE, ts="2026-10-30T00:00:01Z", action=""),
        ]
    )
    recorder.close()

    bom = tmp_path / "bom.jsonl"
    bom.write_bytes(b"\xef\xbb\xbf" + plain.read_bytes())

    events = read_trace(bom)
    assert [event.action for event in events] == ["kb.search", ""]
    assert [event.kind for event in iter_trace(bom)] == [
        EventKind.TOOL_CALL,
        EventKind.NOTE,
    ]


def test_genregress_accepts_a_bom_trace(tmp_path):
    """RT-05 through the CLI: read_trace is what genregress uses."""
    plain = tmp_path / "trace.jsonl"
    recorder = Recorder(plain)
    recorder.record_many(
        [
            AgentEvent(
                kind=EventKind.TOOL_CALL,
                ts="2026-10-30T00:00:00Z",
                agent="support-agent",
                action="kb.search",
            )
        ]
    )
    recorder.close()

    bom = tmp_path / "trace-bom.jsonl"
    bom.write_bytes(b"\xef\xbb\xbf" + plain.read_bytes())

    result = _run_cli(
        "genregress",
        str(bom),
        "-d",
        str(tmp_path / "cases"),
        cwd=tmp_path,
        env={"PYTHONIOENCODING": "utf-8"},
    )

    assert result.returncode == 0, result.stderr
    assert len(list((tmp_path / "cases").glob("*.yaml"))) == 1


# ----------------------------------------------------------------------
# RT-06: a half-written JSONL line must say which line is broken
# ----------------------------------------------------------------------
def test_read_trace_reports_the_broken_line_number(tmp_path):
    trace = tmp_path / "half.jsonl"
    trace.write_text(
        '{"kind": "note", "ts": "2026-10-30T00:00:00Z", "action": "", "inputs": {}, '
        '"outputs": {}, "error": null, "payload": {}, "tags": []}\n'
        '{"kind": "note", "ts": "2026-10-30T00:00:00Z", "act',
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as caught:
        read_trace(trace)

    message = str(caught.value)
    assert "half.jsonl" in message
    assert "line 2" in message


# ----------------------------------------------------------------------
# CLI-layer handoff: tolerant chain reads, no bare ChainError tracebacks
# ----------------------------------------------------------------------
def _write_private_key(path: Path, private_key) -> Path:
    """Serialise a keypair fixture's private key the way `keygen` does."""
    from cryptography.hazmat.primitives import serialization

    path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


def test_utf8_bom_chain_works_in_every_read_command(tmp_path, populated_chain):
    """A BOM'd chain must be readable by verify/--seal, evidence, dashboard, digest."""
    populated_chain.seal_chain()
    plain = tmp_path / "chain.json"
    populated_chain.save(plain)

    bom_chain = tmp_path / "chain-bom.json"
    bom_chain.write_bytes(b"\xef\xbb\xbf" + plain.read_bytes())
    seal = populated_chain.to_dict()["seal"]
    bom_seal = tmp_path / "seal-bom.json"
    bom_seal.write_bytes(b"\xef\xbb\xbf" + json.dumps(seal, indent=2).encode("utf-8"))

    env = {"PYTHONIOENCODING": "utf-8"}

    verify = _run_cli("verify", str(bom_chain), cwd=tmp_path, env=env)
    assert verify.returncode == 0, verify.stderr
    assert b"PASS" in verify.stdout

    sealed = _run_cli(
        "verify", str(bom_chain), "--seal", str(bom_seal), cwd=tmp_path, env=env
    )
    assert sealed.returncode == 0, sealed.stderr
    assert b"PASS" in sealed.stdout

    digest = _run_cli("digest", str(bom_chain), cwd=tmp_path, env=env)
    assert digest.returncode == 0, digest.stderr
    assert len(digest.stdout.strip()) == 64  # sha256 hex digest

    evidence = _run_cli(
        "evidence", str(bom_chain), "-d", str(tmp_path / "evidence"),
        cwd=tmp_path, env=env,
    )
    assert evidence.returncode == 0, evidence.stderr
    assert (tmp_path / "evidence" / "evidence-pack.json").exists()

    dashboard = _run_cli(
        "dashboard", str(bom_chain), "-o", str(tmp_path / "dash.html"),
        cwd=tmp_path, env=env,
    )
    assert dashboard.returncode == 0, dashboard.stderr
    assert (tmp_path / "dash.html").exists()

    # The optional AIBOM document is read by the same tolerant path.
    bom_aibom = tmp_path / "aibom-bom.json"
    bom_aibom.write_bytes(b"\xef\xbb\xbf" + json.dumps({"tools": []}).encode("utf-8"))
    dashboard_with_aibom = _run_cli(
        "dashboard", str(bom_chain), "--aibom", str(bom_aibom),
        "-o", str(tmp_path / "dash-aibom.html"), cwd=tmp_path, env=env,
    )
    assert dashboard_with_aibom.returncode == 0, dashboard_with_aibom.stderr
    assert (tmp_path / "dash-aibom.html").exists()


def test_gbk_chain_is_a_clean_usage_error(tmp_path, keypair, populated_chain):
    """A chain this tool refuses to decode is a domain error, not a traceback."""
    private, _ = keypair
    key_path = _write_private_key(tmp_path / "demo.key", private)

    data = populated_chain.to_dict()
    # Force non-ASCII content so GBK encoding is invalid UTF-8.
    data["records"][0]["reason"] = "只读知识库访问已获批准"
    gbk_chain = tmp_path / "chain-gbk.json"
    gbk_chain.write_bytes(json.dumps(data, ensure_ascii=False).encode("gbk"))
    before = gbk_chain.read_bytes()

    runs = {
        "chain-append": (
            "chain-append", str(gbk_chain), "-k", str(key_path),
            "--actor", "a", "--action", "x", "--decision", "ALLOW", "--reason", "r",
        ),
        "chain-seal": ("chain-seal", str(gbk_chain), "-k", str(key_path)),
        "verify": ("verify", str(gbk_chain)),
        "evidence": ("evidence", str(gbk_chain), "-d", str(tmp_path / "evidence")),
        "dashboard": ("dashboard", str(gbk_chain), "-o", str(tmp_path / "dash.html")),
        "digest": ("digest", str(gbk_chain)),
    }
    for name, args in runs.items():
        result = _run_cli(*args, cwd=tmp_path, env={"PYTHONIOENCODING": "utf-8"})
        assert result.returncode == 2, (name, result.returncode, result.stderr)
        assert b"Traceback" not in result.stderr, (name, result.stderr)
        # The message must name the encoding problem and the fix.
        assert b"UTF-8" in result.stderr, (name, result.stderr)

    # Nothing wrote a replacement chain over the file it could not read.
    assert gbk_chain.read_bytes() == before


def test_malformed_json_is_a_clean_usage_error(tmp_path, populated_chain):
    """Valid encoding but broken content is still a clear exit 2, not a traceback."""
    broken = tmp_path / "broken.json"
    broken.write_text('{"records": [', encoding="utf-8")
    env = {"PYTHONIOENCODING": "utf-8"}

    for args in (
        ("digest", str(broken)),
        ("evidence", str(broken), "-d", str(tmp_path / "evidence")),
        ("dashboard", str(broken), "-o", str(tmp_path / "dash.html")),
        ("verify", str(broken)),
    ):
        result = _run_cli(*args, cwd=tmp_path, env=env)
        assert result.returncode == 2, (args[0], result.returncode, result.stderr)
        assert b"Traceback" not in result.stderr, (args[0], result.stderr)
        assert b"not valid JSON" in result.stderr, (args[0], result.stderr)

    # A seal file that parses as JSON but is not a seal is refused the same way.
    populated_chain.seal_chain()
    chain_path = tmp_path / "chain.json"
    populated_chain.save(chain_path)
    bad_seal = tmp_path / "bad-seal.json"
    bad_seal.write_text('{"not": "a seal"}', encoding="utf-8")

    result = _run_cli(
        "verify", str(chain_path), "--seal", str(bad_seal), cwd=tmp_path, env=env
    )
    assert result.returncode == 2, result.stderr
    assert b"Traceback" not in result.stderr
    assert b"cannot verify against seal" in result.stderr


_SLOW_LOAD_HARNESS = r"""
import os, sys, time
from pathlib import Path
from agentproof.core.chain import Chain

marker = Path(os.environ["AGENTPROOF_TEST_MARKER"])
_original_load = Chain.load.__func__


def _marker_load(cls, path, private_key):
    chain = _original_load(cls, path, private_key)
    marker.write_text("loaded", encoding="utf-8")
    # Hold the chain *after* loading it, so the other process can rewrite the
    # file first and this process is the one that loses the race on save.
    time.sleep(2.5)
    return chain


Chain.load = classmethod(_marker_load)

from agentproof.cli import main
sys.exit(main())
"""


def test_concurrent_append_loser_fails_cleanly(tmp_path, keypair, populated_chain):
    """Two real processes append concurrently; the loser exits 1 without a traceback."""
    private, _ = keypair
    key_path = _write_private_key(tmp_path / "demo.key", private)
    chain_path = tmp_path / "chain.json"
    populated_chain.save(chain_path)

    marker = tmp_path / "loaded.marker"
    child_env = _cli_env(
        {
            "PYTHONIOENCODING": "utf-8",
            "AGENTPROOF_TEST_MARKER": str(marker),
        }
    )
    loser = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SLOW_LOAD_HARNESS,
            "chain-append",
            str(chain_path),
            "-k",
            str(key_path),
            "--actor",
            "loser",
            "--action",
            "x",
            "--decision",
            "ALLOW",
            "--reason",
            "r",
        ],
        cwd=str(tmp_path),
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "helper process never reported its load"

        winner = _run_cli(
            "chain-append",
            str(chain_path),
            "-k",
            str(key_path),
            "--actor",
            "winner",
            "--action",
            "y",
            "--decision",
            "ALLOW",
            "--reason",
            "r",
            cwd=tmp_path,
            env={"PYTHONIOENCODING": "utf-8"},
        )
        assert winner.returncode == 0, winner.stderr

        _, loser_stderr = loser.communicate(timeout=60)
    finally:
        if loser.poll() is None:
            loser.kill()
            loser.communicate()

    assert loser.returncode == 1
    assert b"Traceback" not in loser_stderr
    assert b"cannot save chain" in loser_stderr
    assert b"modified by another process" in loser_stderr

    # The winner's record survived; the loser did not silently overwrite it.
    document = json.loads(chain_path.read_text(encoding="utf-8"))
    assert len(document["records"]) == len(populated_chain.to_dict()["records"]) + 1
    assert document["records"][-1]["actor"] == "winner"


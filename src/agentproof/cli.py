"""Command line interface.

Design rules, all of them deliberate:

* **Zero registration.** Every command works without an account, a key, or a
  network connection. That is what makes the tool adoptable inside a
  regulated organization where procurement takes six weeks.
* **Plain files.** A chain is JSON, a trace is JSONL, a case is YAML. An
  auditor can read them without this tool.
* **Exit codes carry meaning.** ``0`` pass, ``1`` verification or regression
  failure, ``2`` usage error. So ``agentproof verify`` drops straight into CI
  without a wrapper script.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from . import __version__
from .capture import Recorder, get_adapter, read_trace
from .core._textio import TextDecodeError, read_text as read_user_text
from .core.chain import (
    Chain,
    ChainError,
    generate_keypair,
    load_private_key,
)
from .core.policy import PolicyError, load_policy
from .core.verify import load_public_key_hex, verify_chain_file
from .evidence import build_aibom, build_evidence_pack
from .regression import generate_cases, load_case, replay

__all__ = ["main"]


def _echo_err(message: str) -> None:
    click.echo(click.style(message, fg="red"), err=True)


def _tolerate_unencodable_output() -> None:
    """Degrade unencodable characters instead of failing the command.

    A redirected stdout/stderr on Windows uses the ANSI code page (cp936,
    cp1252, ...), which cannot represent every character a reason, action,
    path or payload may carry. Writing one used to raise ``UnicodeEncodeError``
    mid-stream: the command died with a traceback, the real exit code became 1
    (indistinguishable from a verification failure) and ``--json`` output was
    truncated into an invalid document. Escaping such characters keeps the exit
    code and the rest of the output meaningful. On a UTF-8 stream this changes
    nothing, because every character is encodable there.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="backslashreplace")
        except (ValueError, OSError):  # pragma: no cover - detached/closed stream
            continue


def _load_json_document(path: str | Path, *, kind: str) -> Any:
    """Read a user-supplied JSON file with the tolerant decode used by core.

    ``core._textio`` accepts UTF-8 (with or without a BOM) and UTF-16 with a
    BOM; it refuses legacy code pages such as GBK with an actionable message
    instead of guessing. Both that refusal and malformed JSON are usage errors
    here: exit 2 with a clear line on stderr, never a traceback.
    """
    try:
        text = read_user_text(path, kind=kind)
    except TextDecodeError as exc:
        _echo_err(str(exc))
        raise SystemExit(2)
    try:
        return json.loads(text)
    except ValueError as exc:
        _echo_err(f"{kind} file {path} is not valid JSON: {exc}")
        raise SystemExit(2)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="agentproof")
def main() -> None:
    """Vendor-neutral regression testing and compliance evidence for AI agents."""
    _tolerate_unencodable_output()


# ----------------------------------------------------------------------
# key management
# ----------------------------------------------------------------------
@main.command("keygen")
@click.option("--out-dir", "-d", default=".", help="Directory to write the keys into.")
@click.option("--name", "-n", default="agentproof", help="Base filename for the keys.")
def keygen(out_dir: str, name: str) -> None:
    """Generate an Ed25519 keypair for signing chains."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    private, public = generate_keypair()

    from cryptography.hazmat.primitives import serialization

    private_path = directory / f"{name}.key"
    public_path = directory / f"{name}.pub"

    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    click.echo(f"private key : {private_path}")
    click.echo(f"public key  : {public_path}")
    click.echo("")
    click.echo(
        click.style(
            "Keep the private key out of version control. Losing it means the "
            "chain can no longer be extended; leaking it means the chain can "
            "no longer be trusted.",
            fg="yellow",
        )
    )


# ----------------------------------------------------------------------
# policy
# ----------------------------------------------------------------------
@main.command("policy-check")
@click.argument("policy_path", type=click.Path(exists=True))
@click.option("--action", "-a", required=True, help="Action to evaluate.")
@click.option(
    "--input",
    "inputs_json",
    default="{}",
    help="JSON object with the action's inputs.",
)
@click.option(
    "--scope",
    "scopes",
    multiple=True,
    help="Scope granted to the caller. Repeatable.",
)
def policy_check(
    policy_path: str, action: str, inputs_json: str, scopes: tuple[str, ...]
) -> None:
    """Evaluate an action against a policy and show the decision."""
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        _echo_err(f"policy error: {exc}")
        raise SystemExit(2)

    try:
        inputs = json.loads(inputs_json) if inputs_json else {}
    except ValueError as exc:
        _echo_err(f"--input is not valid JSON: {exc}")
        raise SystemExit(2)

    evaluation = policy.evaluate(
        action, inputs=inputs, context={"scopes": list(scopes)}
    )

    colour = {
        "ALLOW": "green",
        "DENY": "red",
        "HALT": "yellow",
    }.get(evaluation.decision.value, "white")

    click.echo(f"action    : {action}")
    click.echo(f"decision  : {click.style(evaluation.decision.value, fg=colour)}")
    click.echo(f"rule      : {evaluation.rule_id}")
    click.echo(f"reason    : {evaluation.reason}")
    if evaluation.conditions_checked:
        click.echo("conditions:")
        for key, value in evaluation.conditions_checked.items():
            click.echo(f"  - {key}: {value}")

    if not evaluation.permitted:
        raise SystemExit(1)


# ----------------------------------------------------------------------
# recording
# ----------------------------------------------------------------------
@main.command("record")
@click.argument("trace_path", type=click.Path())
@click.option(
    "--adapter",
    "-A",
    default="generic",
    help="Adapter used to interpret the input events.",
)
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True),
    help="JSONL file of raw framework events to translate and record.",
)
def record(trace_path: str, adapter: str, input_path: str | None) -> None:
    """Translate raw framework events into a normalized trace."""
    adapter_impl = get_adapter(adapter)

    # Read the input *before* opening the output trace, so an unreadable input
    # never leaves an empty trace file behind.
    raw_text: str | None = None
    if input_path:
        try:
            # ``utf-8-sig`` accepts a UTF-8 BOM (some editors add one) and
            # behaves exactly like ``utf-8`` otherwise. Reading a BOM'd file as
            # plain ``utf-8`` makes its first line fail to parse, which used to
            # be "skipped" while the command still exited 0 -- silent data loss.
            raw_text = Path(input_path).read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            _echo_err(
                f"cannot read {input_path} as UTF-8 text: {exc}. "
                "Re-encode the JSONL as UTF-8 (an optional BOM is accepted) and retry."
            )
            raise SystemExit(2)

    recorder = Recorder(trace_path)

    if raw_text is None:
        recorder.close()
        click.echo(f"created empty trace: {trace_path}")
        return

    count = 0
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError as exc:
            _echo_err(f"skipping malformed line: {exc}")
            continue
        recorder.record_many(adapter_impl.translate(raw))
        count += 1

    recorder.close()
    click.echo(f"wrote {count} event(s) to {trace_path} using the {adapter} adapter")


# ----------------------------------------------------------------------
# regression
# ----------------------------------------------------------------------
@main.command("genregress")
@click.argument("trace_path", type=click.Path(exists=True))
@click.option("--out-dir", "-d", default="cases", help="Directory for generated cases.")
@click.option("--name", "-n", default="", help="Base name for the generated case.")
def genregress(trace_path: str, out_dir: str, name: str) -> None:
    """Generate replayable regression cases from a recorded trace."""
    events = read_trace(trace_path)
    cases = generate_cases(events, source_trace=str(trace_path))

    if not cases:
        click.echo(
            click.style(
                "no tool calls found in this trace; nothing to generate",
                fg="yellow",
            )
        )
        return

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    for case in cases:
        base = name or case.name
        out = directory / f"{base}.yaml"
        counter = 1
        while out.exists():
            out = directory / f"{base}-{counter}.yaml"
            counter += 1
        case.save(out)
        click.echo(
            f"wrote {out}  ({len(case.steps)} step(s), "
            f"from {case.created_from}, {len(case.assertions)} assertion(s))"
        )
        click.echo(
            click.style(
                "  review the 'expect' blocks before running this in CI",
                fg="yellow",
            )
        )


@main.command("replay")
@click.argument("case_path", type=click.Path(exists=True))
@click.option(
    "--script",
    "script_path",
    type=click.Path(exists=True),
    help="Python file exposing `target(step) -> dict`.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def replay_command(case_path: str, script_path: str | None, as_json: bool) -> None:
    """Replay a regression case and report the differences."""
    case = load_case(case_path)

    if script_path:
        namespace: dict[str, Any] = {}
        exec(  # noqa: S102 - the user explicitly points at their own script
            Path(script_path).read_text(encoding="utf-8"),
            namespace,
        )
        target = namespace.get("target")
        if not callable(target):
            _echo_err(f"{script_path} must define a callable named 'target'")
            raise SystemExit(2)
    else:
        # No target supplied: echo the expected behaviour. Useful as a
        # dry-run and as a way to check a generated case reads correctly.
        def target(step: dict[str, Any]) -> dict[str, Any]:
            expect = step.get("expect") or {}
            return {
                "decision": expect.get("decision", "allow"),
                "outputs": expect.get("outputs"),
            }

    result = replay(case, target)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(result.render())

    if not result.passed:
        raise SystemExit(1)


# ----------------------------------------------------------------------
# chain
# ----------------------------------------------------------------------
@main.command("chain-new")
@click.argument("chain_path", type=click.Path())
@click.option("--key", "-k", required=True, type=click.Path(exists=True))
@click.option("--subject", "-s", default="", help="What this chain describes.")
def chain_new(chain_path: str, key: str, subject: str) -> None:
    """Create an empty chain bound to a signing key."""
    private_key = load_private_key(key)
    chain = Chain(private_key, subject=subject)
    chain.save(chain_path)
    click.echo(f"created chain {chain.chain_id} at {chain_path}")
    click.echo(f"public key: {chain.public_key_hex}")


@main.command("chain-append")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option("--key", "-k", required=True, type=click.Path(exists=True))
@click.option("--actor", required=True, help="Who requested the action.")
@click.option("--action", required=True, help="The action requested.")
@click.option(
    "--decision",
    required=True,
    type=click.Choice(["ALLOW", "DENY", "HALT"], case_sensitive=False),
)
@click.option("--reason", required=True, help="Why this decision was made.")
@click.option("--policy-id", default="", help="Identifier of the policy applied.")
@click.option("--policy-digest", default="", help="Digest of the policy document.")
@click.option(
    "--inputs-digest",
    default="",
    help="Digest of the inputs. Use `agentproof digest` to compute it.",
)
@click.option("--context", default="{}", help="Extra JSON context to record.")
def chain_append(
    chain_path: str,
    key: str,
    actor: str,
    action: str,
    decision: str,
    reason: str,
    policy_id: str,
    policy_digest: str,
    inputs_digest: str,
    context: str,
) -> None:
    """Append a signed decision receipt to a chain."""
    private_key = load_private_key(key)
    try:
        chain = Chain.load(chain_path, private_key)
    except (ChainError, OSError) as exc:
        _echo_err(f"cannot load chain: {exc}")
        raise SystemExit(2)

    try:
        context_data = json.loads(context) if context else {}
    except ValueError as exc:
        _echo_err(f"--context is not valid JSON: {exc}")
        raise SystemExit(2)

    try:
        receipt = chain.append(
            actor=actor,
            action=action,
            decision=decision.upper(),
            reason=reason,
            policy_id=policy_id,
            policy_digest=policy_digest,
            inputs_digest=inputs_digest,
            context=context_data,
        )
    except ChainError as exc:
        _echo_err(f"cannot append: {exc}")
        raise SystemExit(1)

    try:
        chain.save(chain_path)
    except (ChainError, OSError) as exc:
        # A concurrent writer changing the file, or a disk error, means the
        # receipt is not durably stored: report it and exit non-zero instead of
        # printing "appended" for a write that did not happen.
        _echo_err(f"cannot save chain: {exc}")
        raise SystemExit(1)

    click.echo(f"appended seq {receipt.seq}: {receipt.decision.value} {receipt.action}")
    click.echo(f"record hash: {receipt.record_hash}")


@main.command("chain-seal")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option("--key", "-k", required=True, type=click.Path(exists=True))
@click.option(
    "--out",
    type=click.Path(),
    default="",
    help="Write the seal to this file as well, for out-of-band publication.",
)
def chain_seal(chain_path: str, key: str, out: str) -> None:
    """Seal a chain, producing an anchor for out-of-band publication."""
    private_key = load_private_key(key)
    try:
        chain = Chain.load(chain_path, private_key)
    except (ChainError, OSError) as exc:
        _echo_err(f"cannot load chain: {exc}")
        raise SystemExit(2)

    try:
        seal = chain.seal_chain()
    except ChainError as exc:
        _echo_err(f"cannot seal: {exc}")
        raise SystemExit(1)

    try:
        chain.save(chain_path)
    except (ChainError, OSError) as exc:
        _echo_err(f"cannot save chain: {exc}")
        raise SystemExit(1)

    click.echo(f"sealed {seal.record_count} record(s)")
    click.echo(f"seal hash: {seal.seal_hash}")

    if out:
        seal_path = Path(out)
        seal_path.parent.mkdir(parents=True, exist_ok=True)
        seal_path.write_text(
            json.dumps(seal.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        click.echo(f"wrote seal to {seal_path}")
        click.echo(
            click.style(
                "publish this file outside the chain store; without it, a full "
                "rewrite by the key holder cannot be detected",
                fg="yellow",
            )
        )


@main.command("digest")
@click.argument("value", type=click.Path(exists=True))
def digest_command(value: str) -> None:
    """Compute the canonical digest of a JSON file."""
    from .core.canonical import digest_bytes

    raw = _load_json_document(value, kind="JSON")
    click.echo(digest_bytes(raw))


# ----------------------------------------------------------------------
# verification
# ----------------------------------------------------------------------
@main.command("verify")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option(
    "--key",
    "-k",
    type=click.Path(exists=True),
    help="Public key file. Defaults to the key embedded in the chain.",
)
@click.option(
    "--seal",
    "seal_path",
    type=click.Path(exists=True),
    help="A separately published seal file to check the chain against.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def verify_command(
    chain_path: str, key: str | None, seal_path: str | None, as_json: bool
) -> None:
    """Verify a chain offline. Exit code 0 means it passed."""
    public_key = None
    if key:
        from cryptography.hazmat.primitives import serialization

        loaded = serialization.load_pem_public_key(Path(key).read_bytes())
        public_key = loaded

    try:
        result = verify_chain_file(chain_path, public_key)
    except (ValueError, FileNotFoundError) as exc:
        _echo_err(str(exc))
        raise SystemExit(2)

    # An externally published seal replaces the embedded one for comparison.
    if seal_path:
        from .core.chain import Seal
        from .core.receipt import Receipt
        from .core.verify import verify_receipts

        data = _load_json_document(chain_path, kind="chain")
        seal_data = _load_json_document(seal_path, kind="seal")
        try:
            receipts = [Receipt.from_dict(r) for r in data.get("records", [])]
            seal = Seal.from_dict(seal_data)
            if public_key is None:
                public_key = load_public_key_hex(data["public_key"])
        except (KeyError, TypeError, ValueError) as exc:
            _echo_err(f"cannot verify against seal: {exc}")
            raise SystemExit(2)
        result = verify_receipts(receipts, public_key, seal=seal)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(result.render())

    if not result.ok:
        raise SystemExit(1)


# ----------------------------------------------------------------------
# evidence
# ----------------------------------------------------------------------
@main.command("evidence")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option("--out-dir", "-d", default="evidence", help="Directory for the pack.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "both"], case_sensitive=False),
    default="both",
)
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    help="Control framework to map against. Repeatable.",
)
def evidence_command(
    chain_path: str, out_dir: str, fmt: str, frameworks: tuple[str, ...]
) -> None:
    """Export a deployer evidence pack from a chain."""
    from .core.receipt import Receipt
    from .core.verify import verify_receipts

    data = _load_json_document(chain_path, kind="chain")
    public_key = load_public_key_hex(data["public_key"])

    receipts = [Receipt.from_dict(r) for r in data.get("records", [])]
    seal_data = data.get("seal")
    seal = None
    if seal_data:
        from .core.chain import Seal

        seal = Seal.from_dict(seal_data)

    verification = verify_receipts(receipts, public_key, seal=seal)

    chain = Chain.from_records(
        receipts,
        public_key,
        chain_id=data.get("chain_id", ""),
        subject=data.get("subject", ""),
        seal=seal,
    )

    pack = build_evidence_pack(
        chain, verification=verification, frameworks=list(frameworks) or None
    )

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    if fmt in ("json", "both"):
        path = pack.save_json(directory / "evidence-pack.json")
        click.echo(f"wrote {path}")
    if fmt in ("markdown", "both"):
        path = pack.save_markdown(directory / "evidence-pack.md")
        click.echo(f"wrote {path}")

    click.echo("")
    click.echo(
        f"integrity: {'PASS' if pack.verification.get('ok') else 'FAIL'} "
        f"({pack.verification.get('records_checked', 0)} records)"
    )
    click.echo(f"decisions: {pack.summary.get('total_decisions', 0)}")


@main.command("aibom")
@click.argument("trace_path", type=click.Path(exists=True))
@click.option("--out-dir", "-d", default=".", help="Directory for the AIBOM files.")
@click.option("--subject", "-s", default="", help="What this inventory covers.")
def aibom_command(trace_path: str, out_dir: str, subject: str) -> None:
    """Build an AI Bill of Materials from a recorded trace."""
    events = read_trace(trace_path)
    aibom = build_aibom(events, subject=subject, source_trace=str(trace_path))

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    json_path = aibom.save_json(directory / "aibom.json")
    md_path = aibom.save_markdown(directory / "aibom.md")
    click.echo(f"wrote {json_path}")
    click.echo(f"wrote {md_path}")
    click.echo("")
    click.echo(
        f"{aibom.summary.get('agent_count', 0)} agent(s), "
        f"{aibom.summary.get('tool_count', 0)} tool(s), "
        f"{aibom.summary.get('model_count', 0)} model(s), "
        f"{aibom.summary.get('error_events', 0)} error(s)"
    )


@main.command("dashboard")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option(
    "--out",
    "-o",
    type=click.Path(),
    default="agentproof-dashboard.html",
    help="Where to write the HTML file.",
)
@click.option(
    "--aibom",
    "aibom_path",
    type=click.Path(exists=True),
    help="Optional AI Bill of Materials JSON to include.",
)
@click.option("--title", default="", help="Document title.")
def dashboard_command(
    chain_path: str, out: str, aibom_path: str | None, title: str
) -> None:
    """Render a self-contained HTML evidence dashboard.

    The output is a single file with no external requests. It opens offline
    from disk and can be forwarded to an auditor as-is.
    """
    from .core.receipt import Receipt
    from .core.verify import verify_receipts
    from .dashboard import render_dashboard

    data = _load_json_document(chain_path, kind="chain")
    public_key = load_public_key_hex(data["public_key"])

    receipts = [Receipt.from_dict(r) for r in data.get("records", [])]
    seal = None
    if data.get("seal"):
        from .core.chain import Seal

        seal = Seal.from_dict(data["seal"])

    verification = verify_receipts(receipts, public_key, seal=seal)

    chain = Chain.from_records(
        receipts,
        public_key,
        chain_id=data.get("chain_id", ""),
        subject=data.get("subject", ""),
        seal=seal,
    )
    pack = build_evidence_pack(chain, verification=verification)

    aibom = None
    if aibom_path:
        aibom = _load_json_document(aibom_path, kind="aibom")

    html_text = render_dashboard(
        data,
        subject=data.get("subject", ""),
        verification=verification.to_dict(),
        aibom=aibom,
        title=title,
        limitations=pack.limitations,
        control_map=pack.control_map,
    )

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_text, encoding="utf-8")

    size_kb = len(html_text.encode("utf-8")) / 1024
    click.echo(f"wrote {out_path}  ({size_kb:.0f} KB, self-contained, no external requests)")
    click.echo("")
    click.echo(f"integrity: {'PASS' if verification.ok else 'FAIL'} "
               f"({verification.records_checked} records)")
    click.echo("open it in any browser, including offline")


# ----------------------------------------------------------------------
# scanner (PLG wedge) & insurability & cloud SaaS server
# ----------------------------------------------------------------------
@main.command("scan")
@click.argument("target_dir", default=".", type=click.Path(exists=True))
@click.option(
    "--init-policy",
    "init_policy_path",
    type=click.Path(),
    default="",
    help="Synthesize a starter fail-closed policy.yaml from discovered tools.",
)
@click.option(
    "--subject",
    default="discovered-agent-system",
    help="Subject name when generating a starter policy.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default=None,
    help="Exit 1 if any finding meets or exceeds this severity.",
)
def scan_command(
    target_dir: str,
    init_policy_path: str,
    subject: str,
    as_json: bool,
    fail_on: str | None,
) -> None:
    """Scan a workspace for Shadow MCP servers and unguarded agent tools."""
    from .scanner.report import run_workspace_scan, save_starter_policy

    report = run_workspace_scan(target_dir)

    if init_policy_path:
        saved = save_starter_policy(report, init_policy_path, subject=subject)
        if not as_json:
            click.echo(f"wrote starter policy to {saved}")

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(report.render())

    if fail_on:
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        threshold = rank[fail_on.upper()]
        if any(rank.get(f.severity.value, 0) >= threshold for f in report.findings):
            raise SystemExit(1)


@main.command("insurability")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option(
    "--notarized-count",
    default=0,
    type=int,
    help="Number of receipts counter-signed by AgentProof Cloud Witness.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def insurability_command(
    chain_path: str, notarized_count: int, as_json: bool
) -> None:
    """Compute the Lloyd's AIUC-1 insurability scorecard for a chain."""
    from .core.receipt import Receipt
    from .core.verify import verify_receipts
    from .evidence.insurability import compute_insurability_score

    data = _load_json_document(chain_path, kind="chain")
    public_key = load_public_key_hex(data["public_key"])
    receipts = [Receipt.from_dict(r) for r in data.get("records", [])]
    seal = None
    if data.get("seal"):
        from .core.chain import Seal

        seal = Seal.from_dict(data["seal"])

    verification = verify_receipts(receipts, public_key, seal=seal)
    chain = Chain.from_records(
        receipts,
        public_key,
        chain_id=data.get("chain_id", ""),
        subject=data.get("subject", ""),
        seal=seal,
    )
    scorecard = compute_insurability_score(
        chain, verification=verification, notarized_count=notarized_count
    )

    if as_json:
        click.echo(json.dumps(scorecard.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(f"AIUC-1 Insurability Scorecard — {scorecard.subject}")
        click.echo(f"Score             : {scorecard.insurability_score}/100")
        click.echo(f"Underwriting Tier : {scorecard.underwriting_tier}")
        click.echo(f"Premium Impact    : {scorecard.premium_adjustment}")
        for s in scorecard.strengths:
            click.echo(f"  + {s}")
        for r in scorecard.remediations:
            click.echo(f"  ! {r}")

    if scorecard.underwriting_tier == "UNINSURABLE":
        raise SystemExit(1)


@main.command("cloud-serve")
@click.option("--host", default="127.0.0.1", help="Bind host.")
@click.option("--port", default=8780, type=int, help="Bind port.")
@click.option(
    "--db",
    "db_path",
    default="agentproof-cloud.db",
    help="SQLite ledger database path.",
)
def cloud_serve_command(host: str, port: int, db_path: str) -> None:
    """Launch the AgentProof Cloud multi-tenant SaaS server & web console."""
    from .cloud.server import run_cloud_server

    run_cloud_server(host=host, port=port, db_path=db_path)


@main.command("export")
@click.argument("chain_path", type=click.Path(exists=True))
@click.option(
    "--target",
    "-t",
    required=True,
    type=click.Choice(["vanta", "drata", "datadog"], case_sensitive=False),
    help="Target GRC or SIEM platform (Vanta, Drata, Datadog).",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(),
    default="",
    help="Optional file path to write the formatted export JSON.",
)
@click.option(
    "--notarized-count",
    default=0,
    type=int,
    help="Number of receipts counter-signed by AgentProof Cloud Witness.",
)
@click.option(
    "--push-url",
    default="",
    help="Optional webhook/API URL to POST the formatted payload to.",
)
@click.option(
    "--api-token",
    default="",
    help="Bearer token or API key when pushing to Vanta/Drata/Datadog.",
)
def export_command(
    chain_path: str,
    target: str,
    out: str,
    notarized_count: int,
    push_url: str,
    api_token: str,
) -> None:
    """Export cryptographic compliance evidence to Vanta, Drata, or Datadog."""
    from .core.receipt import Receipt
    from .core.verify import verify_receipts
    from .exporters import build_target_export, push_export_payload

    data = _load_json_document(chain_path, kind="chain")
    public_key = load_public_key_hex(data["public_key"])
    receipts = [Receipt.from_dict(r) for r in data.get("records", [])]
    seal = None
    if data.get("seal"):
        from .core.chain import Seal

        seal = Seal.from_dict(data["seal"])

    verification = verify_receipts(receipts, public_key, seal=seal)
    chain = Chain.from_records(
        receipts,
        public_key,
        chain_id=data.get("chain_id", ""),
        subject=data.get("subject", ""),
        seal=seal,
    )
    payload = build_target_export(
        target,
        chain,
        verification=verification,
        notarized_count=notarized_count,
    )
    formatted = json.dumps(payload, indent=2, ensure_ascii=False)

    if out:
        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(formatted, encoding="utf-8")
        click.echo(f"wrote {target} export payload to {out_path}")
    else:
        click.echo(formatted)

    if push_url:
        res = push_export_payload(payload, push_url=push_url, api_token=api_token)
        click.echo(f"pushed to {push_url}: HTTP {res['status_code']}")


@main.command("scout")
@click.option(
    "--dir",
    "local_dir",
    type=click.Path(exists=True),
    default=None,
    help="Scan local repositories under this directory for customer outreach leads.",
)
@click.option(
    "--github-query",
    default="",
    help="Search public GitHub repositories via API (e.g. 'filename:mcp.json mcpServers').",
)
@click.option("--limit", default=15, type=int, help="Max GitHub items to inspect.")
@click.option("--out-dir", "-d", default="leads", help="Directory to write lead bundles.")
@click.option(
    "--website-url",
    default="https://neon-sawine-352869.netlify.app",
    help="Public landing page URL embedded into generated outreach templates.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON summary.")
def scout_command(
    local_dir: str | None,
    github_query: str,
    limit: int,
    out_dir: str,
    website_url: str,
    as_json: bool,
) -> None:
    """Discover risky AI agent / MCP repos and generate ready-to-send outreach packages."""
    from .growth import discover_github_leads, scout_local_repositories

    if github_query:
        summary = discover_github_leads(
            query=github_query,
            limit=limit,
            out_dir=out_dir,
            website_url=website_url,
        )
    else:
        target = local_dir or "."
        summary = scout_local_repositories(
            target,
            out_dir=out_dir,
            website_url=website_url,
        )

    if as_json:
        click.echo(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(
            f"AgentProof Scout complete: scanned {summary.scanned_count} target(s), "
            f"qualified {summary.qualified_count} lead(s) -> {summary.output_dir}"
        )
        for lead in summary.leads:
            click.echo(
                f"  - [{lead.security_grade} / {lead.risk_score}] {lead.repo_name}: "
                f"{lead.findings_count} findings -> {lead.output_dir}"
            )


if __name__ == "__main__":
    sys.exit(main())

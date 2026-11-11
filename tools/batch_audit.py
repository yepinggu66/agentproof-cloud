"""Batch-generate signed audit reports for public agent repositories.

Reads only public default branches, writes nothing back to GitHub, and produces
one signed report per repository plus an index. This is the tool behind the
first outbound audit batch.

Usage
-----
    python tools/batch_audit.py                       # curated 10-repo list
    python tools/batch_audit.py --repos owner/a,owner/b --out .tmp/audit-batch
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tools.audit_report import (  # noqa: E402
    AuditResult,
    audit_paths,
    load_or_create_key,
    render_html,
    render_markdown,
    sign_result,
)
from tools.leadgen import GitHub  # noqa: E402

DEFAULT_REPOS = [
    "modelcontextprotocol/servers",
    "openai/openai-agents-python",
    "langchain-ai/langgraph",
    "crewAIInc/crewAI",
    "microsoft/autogen",
    "Significant-Gravitas/AutoGPT",
    "geekan/MetaGPT",
    "run-llama/llama_index",
    "BerriAI/litellm",
    "BeehiveInnovations/pal-mcp-server",
]

MCP_NAMES = {
    "mcp.json", "mcp.config.json", ".mcp.json", "claude_desktop_config.json",
    "claude_config.json", "mcp_config.json", "servers.json",
}
PY_HINTS = ("tool", "agent", "mcp", "server", "main", "executor", "shell", "sandbox")


@dataclass
class BatchRow:
    repo: str
    grade: str
    findings: int
    critical: int
    high: int
    files: int
    report: str
    error: str = ""


def pick_files(github: GitHub, full_name: str, branch: str, max_files: int) -> list[tuple[str, str]]:
    tree = github.tree(full_name, branch)
    blobs = [item for item in tree if item.get("type") == "blob"]
    mcp = [
        item["path"] for item in blobs
        if Path(item["path"]).name.lower() in MCP_NAMES
    ]
    py = [
        item["path"] for item in blobs
        if item["path"].endswith(".py")
        and any(hint in item["path"].lower() for hint in PY_HINTS)
    ]
    py.sort(key=lambda path: (path.count("/"), len(path)))
    chosen: list[str] = mcp[: max_files // 2] + py[: max_files - min(len(mcp), max_files // 2)]
    contents: list[tuple[str, str]] = []
    for path in chosen:
        text = github.file_text(full_name, path)
        if text:
            contents.append((path, text))
    return contents


def audit_repo(github: GitHub, full_name: str, out_dir: Path, key_path: Path, max_files: int) -> BatchRow:
    meta = github.repo(full_name) or {}
    branch = meta.get("default_branch") or "main"
    repo_dir = out_dir / full_name.replace("/", "__")
    src_dir = repo_dir / "_source"
    src_dir.mkdir(parents=True, exist_ok=True)

    contents = pick_files(github, full_name, branch, max_files)
    paths: list[Path] = []
    for index, (remote_path, text) in enumerate(contents):
        name = Path(remote_path).name
        local = src_dir / f"{index:02d}_{name}"
        local.write_text(text, encoding="utf-8")
        paths.append(local)

    result = audit_paths(paths, client=full_name, prepared_by="AgentProof.cloud")
    private_pem, public_pem = load_or_create_key(key_path)
    signature = sign_result(result, private_pem, public_pem)
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "report.html").write_text(render_html(result, signature), encoding="utf-8")
    (repo_dir / "report.md").write_text(render_markdown(result, signature), encoding="utf-8")
    (repo_dir / "report.json").write_text(
        json.dumps({"result": result.__dict__, "signature": signature}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (repo_dir / "public-key.pem").write_bytes(public_pem)
    counts = result.summary()["counts"]
    return BatchRow(
        repo=full_name,
        grade=result.grade,
        findings=len(result.findings),
        critical=counts["critical"],
        high=counts["high"],
        files=len(result.files),
        report=str(repo_dir / "report.html"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch signed audits for public agent repos.")
    parser.add_argument("--repos", help="comma separated owner/repo list")
    parser.add_argument("--out", default=".tmp/audit-batch")
    parser.add_argument("--max-files", type=int, default=6)
    parser.add_argument("--key", default=str(ROOT / ".tmp" / "audit-signing-key.pem"))
    args = parser.parse_args(argv)

    repos = (
        [item.strip() for item in args.repos.split(",") if item.strip()]
        if args.repos
        else DEFAULT_REPOS
    )
    github = GitHub.authenticate()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = Path(args.key)

    rows: list[BatchRow] = []
    for index, repo in enumerate(repos, start=1):
        print(f"[{index}/{len(repos)}] {repo}", file=sys.stderr)
        try:
            row = audit_repo(github, repo, out_dir, key_path, args.max_files)
        except Exception as exc:  # keep the batch alive
            row = BatchRow(repo=repo, grade="—", findings=0, critical=0, high=0, files=0, report="", error=f"{type(exc).__name__}: {exc}")
        rows.append(row)
        print(f"    grade={row.grade} findings={row.findings} critical={row.critical} high={row.high} err={row.error or '-'}", file=sys.stderr)
        time.sleep(0.4)

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with (out_dir / "index.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(BatchRow.__dataclass_fields__))
        writer.writeheader()
        writer.writerows([row.__dict__ for row in rows])
    lines = [
        "# AgentProof 批次审计索引",
        "",
        f"生成时间：{generated_at} · 仓库数：{len(rows)}",
        "",
        "| 仓库 | 评级 | 发现 | 致命/高危 | 报告 |",
        "|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=lambda item: (-item.critical, -item.high, item.repo)):
        lines.append(
            f"| [{row.repo}](https://github.com/{row.repo}) | **{row.grade}** | {row.findings} "
            f"| {row.critical}/{row.high} | `{row.report}` |"
        )
    (out_dir / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out_dir / 'index.md'} and {len(rows)} report folders")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

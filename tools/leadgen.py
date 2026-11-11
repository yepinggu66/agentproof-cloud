"""Batch static security triage of public GitHub agent / MCP repositories.

This is the lead-generation tool for AgentProof.cloud: it reads only the
public default branch of a repository (no clone, no dependency install, no
execution of target code), runs the same scanner that powers the website, and
writes one shareable report per repository plus a lead list.

Usage
-----
    python tools/leadgen.py --search "mcp server in:name" --limit 5
    python tools/leadgen.py --repos owner/repo,owner/repo2 --out .tmp/leadgen
    python tools/leadgen.py --repos-file repos.txt --max-files 6 --min-stars 50

Outputs (default ``.tmp/leadgen``):
    leads.csv                 one row per repo: grade, finding counts, report path
    summary.json              machine-readable aggregate
    reports/<owner>__<repo>.md  human-readable report, safe to send to a CTO

Ethics / limits
---------------
* Public repositories only, read-only GitHub API, no cloning or execution.
* Secret-looking values are redacted from every report before writing.
* Rate limits are respected; the tool stops cleanly instead of hammering.
* Reports are static-analysis findings, not exploit proof. Send them only
  where unsolicited security reports are welcome (or after opt-in).
"""

from __future__ import annotations

import argparse
import csv
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from server.scan import ScanInputError, scan  # noqa: E402

API = "https://api.github.com"
USER_AGENT = "AgentProof-leadgen/1.0 (+https://agentproof.cloud)"
MCP_NAMES = {
    "mcp.json",
    "mcp.config.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "claude_config.json",
    "mcp_config.json",
    "servers.json",
}
PY_HINTS = (
    "tool", "agent", "mcp", "server", "main", "cli", "runtime", "executor",
    "sandbox", "browser", "shell", "plugin", "skill",
)
SECRET_REDACTIONS = [
    (re.compile(r"(sk-[A-Za-z0-9_-]{8,})"), "sk-***redacted***"),
    (re.compile(r"(ghp_[A-Za-z0-9]{8,})"), "ghp_***redacted***"),
    (re.compile(r"(AKIA[0-9A-Z]{8,})"), "AKIA***redacted***"),
    (re.compile(r"(xox[baprs]-[A-Za-z0-9-]{8,})"), "xox***redacted***"),
    (re.compile(r"(postgres(?:ql)?://[^:\s]+:)([^@\s]+)(@)", re.IGNORECASE), r"\1***\3"),
]
MAX_BYTES = 200_000


# ---------------------------------------------------------------------------
# GitHub client
# ---------------------------------------------------------------------------


class GitHub:
    def __init__(self, token: str, *, timeout: int = 30) -> None:
        self.token = token
        self.timeout = timeout
        self.requests = 0

    @classmethod
    def authenticate(cls) -> "GitHub":
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
        if not token:
            try:
                token = subprocess.run(
                    ["gh", "auth", "token"], capture_output=True, text=True, timeout=15
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                token = ""
        if not token:
            raise SystemExit(
                "No GitHub token. Run `gh auth login` or set GH_TOKEN "
                "(unauthenticated search is 10 req/min and will be painful)."
            )
        return cls(token)

    def get(self, path: str, *, raw: bool = False) -> Any:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        url = path if path.startswith("https://") else API + path
        for attempt in range(3):
            request = urllib.request.Request(url, headers=headers)
            try:
                self.requests += 1
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = response.read()
                    if raw:
                        return body.decode("utf-8", errors="replace")
                    return json.loads(body.decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as exc:
                if exc.code in {403, 429} and attempt < 2:
                    reset = exc.headers.get("x-ratelimit-reset")
                    wait = 20
                    if reset and reset.isdigit():
                        wait = max(5, min(300, int(reset) - int(time.time()) + 2))
                    print(f"    rate limited, waiting {wait}s…", file=sys.stderr)
                    time.sleep(wait)
                    continue
                if exc.code == 404:
                    return None
                raise
            except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
                if attempt < 2:
                    print(f"    network hiccup ({exc}), retrying…", file=sys.stderr)
                    time.sleep(2 + attempt * 3)
                    continue
                raise
        return None

    def search_code_repos(self, query: str, limit: int) -> list[dict[str, Any]]:
        """Find repositories that contain files matching a GitHub code query.

        The code-search payload omits star counts, so repository metadata is
        fetched for the candidates and they are ranked by stars.
        """
        encoded = urllib.parse.quote(query)
        payload = self.get(f"/search/code?q={encoded}&per_page=30")
        if not payload or not payload.get("items"):
            return []
        repos: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in payload["items"]:
            repo = item.get("repository") or {}
            full_name = repo.get("full_name")
            if not full_name or full_name in seen:
                continue
            seen.add(full_name)
            repos.append({"full_name": full_name, "stargazers_count": 0})
            if len(repos) >= 40:
                break
        for item in repos:
            meta = self.repo(item["full_name"]) or {}
            item["stargazers_count"] = int(meta.get("stargazers_count") or 0)
        repos.sort(key=lambda item: item["stargazers_count"], reverse=True)
        return repos[: max(limit * 2, 5)]

    def search_repos(self, query: str, limit: int) -> list[dict[str, Any]]:
        encoded = urllib.parse.quote(query)
        payload = self.get(f"/search/repositories?q={encoded}&sort=stars&order=desc&per_page={min(limit * 2, 100)}")
        if not payload:
            return []
        return payload.get("items", [])[:limit]

    def repo(self, full_name: str) -> dict[str, Any] | None:
        return self.get(f"/repos/{full_name}")

    def tree(self, full_name: str, branch: str) -> list[dict[str, Any]]:
        payload = self.get(f"/repos/{full_name}/git/trees/{urllib.parse.quote(branch)}?recursive=1")
        if not payload:
            return []
        return payload.get("tree", [])

    def file_text(self, full_name: str, path: str) -> str | None:
        encoded = urllib.parse.quote(path, safe="/")
        text = self.get(f"/repos/{full_name}/contents/{encoded}", raw=True)
        if text is None:
            return None
        if len(text.encode("utf-8", errors="ignore")) > MAX_BYTES:
            return None
        return text


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


@dataclass
class RepoReport:
    full_name: str
    url: str
    stars: int
    license: str
    description: str
    grade: str = "—"
    findings: int = 0
    critical: int = 0
    high: int = 0
    mcp_files: int = 0
    python_files: int = 0
    scans: list[dict[str, Any]] = field(default_factory=list)
    top: list[dict[str, Any]] = field(default_factory=list)
    report_path: str = ""
    error: str = ""

    def as_row(self) -> dict[str, Any]:
        top_rule = self.top[0]["id"] if self.top else ""
        top_title = self.top[0]["title"] if self.top else ""
        return {
            "repo": self.full_name,
            "url": self.url,
            "stars": self.stars,
            "license": self.license,
            "grade": self.grade,
            "findings": self.findings,
            "critical": self.critical,
            "high": self.high,
            "mcp_files": self.mcp_files,
            "python_files": self.python_files,
            "top_rule": top_rule,
            "top_title": top_title,
            "report": self.report_path,
            "error": self.error,
        }


def python_is_interesting(text: str) -> bool:
    return bool(
        re.search(r"@(?:tool|function_tool|mcp\.tool|app\.tool)\b", text)
        or re.search(r"\b(?:subprocess|os\.system|eval|exec|pickle|shutil\.rmtree)\b", text)
        or re.search(r"\bdef\s+\w*(?:shell|exec|command|run_cmd|tool)\w*\s*\(", text, re.I)
    )


def redact(text: str) -> str:
    for pattern, replacement in SECRET_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def analyse_repo(github: GitHub, full_name: str, *, max_files: int) -> RepoReport:
    meta = github.repo(full_name)
    if not meta:
        return RepoReport(full_name=full_name, url=f"https://github.com/{full_name}", stars=0, license="", description="", error="repo not found or private")

    report = RepoReport(
        full_name=full_name,
        url=f"https://github.com/{full_name}",
        stars=int(meta.get("stargazers_count") or 0),
        license=(meta.get("license") or {}).get("spdx_id") or "none",
        description=(meta.get("description") or "").strip(),
    )
    branch = meta.get("default_branch") or "main"
    tree = github.tree(full_name, branch)
    if not tree:
        report.error = "empty tree"
        return report

    files = [item for item in tree if item.get("type") == "blob"]
    mcp_paths = [
        item["path"] for item in files
        if Path(item["path"]).name.lower() in MCP_NAMES
    ]
    py_paths = [
        item["path"] for item in files
        if item["path"].endswith(".py")
        and any(hint in item["path"].lower() for hint in PY_HINTS)
    ]
    # prefer shallow, likely entry points
    py_paths.sort(key=lambda path: (path.count("/"), len(path)))
    report.mcp_files = len(mcp_paths)
    report.python_files = len(py_paths)

    scans: list[dict[str, Any]] = []
    for path in mcp_paths[:max_files]:
        text = github.file_text(full_name, path)
        if not text:
            continue
        try:
            result = scan("mcp", text, subject=f"{full_name}:{path}")
        except ScanInputError as exc:
            scans.append({"path": path, "kind": "mcp", "error": str(exc)})
            continue
        scans.append(_scan_record(path, "mcp", result))

    py_budget = max(0, max_files - len(mcp_paths[:max_files]))
    for path in py_paths[: py_budget * 3]:
        if py_budget <= 0:
            break
        text = github.file_text(full_name, path)
        if not text:
            continue
        if not python_is_interesting(text):
            continue
        try:
            result = scan("python", text, subject=f"{full_name}:{path}")
        except ScanInputError:
            continue
        py_budget -= 1
        scans.append(_scan_record(path, "python", result))

    report.scans = scans
    scored = [item for item in scans if "grade" in item]
    if scored:
        report.grade = max((item["grade"] for item in scored), key=lambda g: "ABCDF".index(g))
        report.findings = sum(item["findings"] for item in scored)
        report.critical = sum(item["critical"] for item in scored)
        report.high = sum(item["high"] for item in scored)
        merged: dict[str, dict[str, Any]] = {}
        for item in scored:
            for finding in item["top_findings"]:
                merged.setdefault(finding["id"], finding | {"path": item["path"]})
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        report.top = sorted(merged.values(), key=lambda f: (order.get(f["severity"], 9), f["id"]))[:8]
    return report


def _scan_record(path: str, kind: str, result: Any) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "path": path,
        "kind": kind,
        "grade": result.grade,
        "score": result.score,
        "findings": len(result.findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "top_findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "detail": redact(f.detail),
                "evidence": redact(f.evidence),
                "remediation": f.remediation,
            }
            for f in result.findings[:5]
        ],
        "policy_yaml": redact(result.policy_yaml),
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def render_report(report: RepoReport, generated_at: str) -> str:
    lines = [
        f"# AgentProof 免费安全体检 — `{report.full_name}`",
        "",
        f"- 仓库：{report.url}",
        f"- Stars：{report.stars:,} · License：{report.license}",
        f"- 扫描时间：{generated_at}",
        f"- 总体评级：**{report.grade}** · 命中问题：{report.findings} 项"
        + (f"（致命 {report.critical} / 高危 {report.high}）" if report.findings else ""),
        "",
        "> 本报告基于公开仓库默认分支的静态分析，未克隆、未安装依赖、未执行目标代码。",
        "> 它是风险线索，不是漏洞证明；请以人工复核为准。",
        "",
    ]
    if report.error:
        lines += [f"扫描失败：{report.error}", ""]
        return "\n".join(lines)

    if not report.scans:
        lines += [
            "没有在默认分支中找到可扫描的 `mcp.json` 或 agent 工具代码。",
            "如果你的 agent 配置在别的路径，或希望扫描私有仓库，可在 https://agentproof.cloud 粘贴配置做免费扫描。",
            "",
        ]
        return "\n".join(lines)

    lines += ["## 被扫描的文件", "", "| 文件 | 类型 | 评级 | 命中数 |", "|---|---|---|---|"]
    for item in report.scans:
        if "grade" not in item:
            lines.append(f"| `{item['path']}` | {item['kind']} | 解析失败 | — |")
        else:
            lines.append(f"| `{item['path']}` | {item['kind']} | **{item['grade']}** | {item['findings']} |")
    lines.append("")

    if report.top:
        lines += ["## 主要发现", "", "| 严重度 | 规则 | 问题 | 证据（已脱敏） |", "|---|---|---|---|"]
        for finding in report.top:
            evidence = finding["evidence"].replace("|", "\\|")[:160]
            lines.append(
                f"| {SEVERITY_LABEL.get(finding['severity'], finding['severity'])} "
                f"| `{finding['id']}` | {finding['title']} | `{evidence}` |"
            )
        lines.append("")

        lines += ["## 修复建议", ""]
        for finding in report.top[:5]:
            lines.append(f"- **{finding['title']}**（`{finding['path']}`）：{finding['remediation']}")
        lines.append("")

        worst = max(
            (item for item in report.scans if "grade" in item),
            key=lambda item: item["score"],
        )
        lines += [
            "## 可直接落地的默认拒绝策略（节选）",
            "",
            "```yaml",
            "\n".join(worst["policy_yaml"].splitlines()[:24]),
            "```",
            "",
        ]

    lines += [
        "## 这份报告是什么 / 不是什么",
        "",
        "- 是：公开配置与代码的静态风险线索，附带可执行的修复方向与默认拒绝策略。",
        "- 不是：漏洞利用证明、合规认证、法律意见。",
        "- 反馈：如果这不是你希望收到的邮件，回复「停止」即可，我们不会再发送。",
        "",
    ]
    return "\n".join(lines)


def write_outputs(reports: list[RepoReport], out_dir: Path, generated_at: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    for report in reports:
        filename = report.full_name.replace("/", "__") + ".md"
        path = reports_dir / filename
        path.write_text(render_report(report, generated_at), encoding="utf-8")
        report.report_path = str(path)

    rows = [report.as_row() for report in reports]
    with (out_dir / "leads.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "generated_at": generated_at,
        "repos": len(reports),
        "graded": sum(1 for report in reports if report.grade != "—"),
        "with_findings": sum(1 for report in reports if report.findings),
        "by_grade": {
            grade: sum(1 for report in reports if report.grade == grade) for grade in ["A", "B", "C", "D", "F"]
        },
        "results": rows,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# AgentProof 批量体检汇总",
        "",
        f"生成时间：{generated_at} · 仓库数：{len(reports)} · 有发现问题：{summary['with_findings']}",
        "",
        "| 仓库 | 评级 | 问题 | 致命/高危 | 报告 |",
        "|---|---|---|---|---|",
    ]
    for report in sorted(reports, key=lambda item: ("ABCDF".index(item.grade) if item.grade in "ABCDF" else 9), reverse=True):
        name = report.full_name
        lines.append(
            f"| [{name}](https://github.com/{name}) | **{report.grade}** | {report.findings} "
            f"| {report.critical}/{report.high} | `{report.report_path}` |"
        )
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def collect_repos(args: argparse.Namespace, github: GitHub) -> list[str]:
    names: list[str] = []
    if args.repos:
        names += [item.strip() for item in args.repos.split(",") if item.strip()]
    if args.repos_file:
        path = Path(args.repos_file)
        names += [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    if args.search:
        print(f"search: {args.search!r} (limit {args.limit})", file=sys.stderr)
        for item in github.search_repos(args.search, args.limit):
            full_name = item["full_name"]
            stars = int(item.get("stargazers_count") or 0)
            if stars < args.min_stars:
                continue
            names.append(full_name)
    if args.code_search:
        print(f"code search: {args.code_search!r} (limit {args.limit})", file=sys.stderr)
        for item in github.search_code_repos(args.code_search, args.limit):
            stars = int(item.get("stargazers_count") or 0)
            if stars < args.min_stars:
                continue
            names.append(item["full_name"])
    seen: set[str] = set()
    unique = []
    for name in names:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch scan public agent/MCP repositories for risk findings.")
    parser.add_argument("--repos", help="comma separated owner/repo list")
    parser.add_argument("--repos-file", help="file with one owner/repo per line")
    parser.add_argument("--search", help="GitHub search query, e.g. 'mcp server in:name'")
    parser.add_argument("--code-search", help='GitHub code query, e.g. \'"mcpServers" filename:mcp.json\'')
    parser.add_argument("--limit", type=int, default=5, help="max repos from search (default 5)")
    parser.add_argument("--min-stars", type=int, default=0, help="skip repos below this star count")
    parser.add_argument("--max-files", type=int, default=8, help="max files scanned per repo (default 8)")
    parser.add_argument("--out", default=".tmp/leadgen", help="output directory")
    args = parser.parse_args(argv)

    github = GitHub.authenticate()
    names = collect_repos(args, github)
    if not names:
        print("no repositories to scan", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    reports: list[RepoReport] = []
    for index, name in enumerate(names, start=1):
        print(f"[{index}/{len(names)}] {name}", file=sys.stderr)
        try:
            report = analyse_repo(github, name, max_files=args.max_files)
        except Exception as exc:  # keep the batch alive
            report = RepoReport(full_name=name, url=f"https://github.com/{name}", stars=0, license="", description="", error=f"{type(exc).__name__}: {exc}")
        reports.append(report)
        print(
            f"    grade={report.grade} findings={report.findings} "
            f"mcp={report.mcp_files} py={report.python_files} err={report.error or '-'}",
            file=sys.stderr,
        )
        time.sleep(0.4)

    write_outputs(reports, out_dir, generated_at)
    print(f"\nwrote {out_dir / 'leads.csv'}, {out_dir / 'summary.md'}, {out_dir / 'reports/'} ({len(reports)} repos)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

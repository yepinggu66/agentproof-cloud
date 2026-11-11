"""Generate a client-ready, tamper-evident security audit report.

This is the sellable deliverable for the audit service: a self-contained HTML
file (no external requests, print-to-PDF friendly) plus Markdown and JSON,
built from the same static scanner that powers the website.

The report is *signed*: a digest over the findings is signed with an Ed25519
key, and the public key, fingerprint and signature are embedded. That lets a
client verify the report was not edited after delivery — the same "evidence,
not a claim" argument as the product.

Usage
-----
    python tools/audit_report.py --repo path/to/agent-project \
        --client "Acme Support" --out audit/
    python tools/audit_report.py --file tests/sample-dangerous-mcp.json \
        --kind mcp --client "Acme Support" --out docs/sample-audit
    python tools/audit_report.py verify --report audit/report.json \
        --public-key audit/public-key.pem

Static analysis only: nothing is executed, no network is used, no secrets are
printed (values are redacted before rendering).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from server.scan import ScanInputError, scan  # noqa: E402
from server import signing  # noqa: E402

MCP_NAMES = {
    "mcp.json", "mcp.config.json", ".mcp.json", "claude_desktop_config.json",
    "claude_config.json", "mcp_config.json", "servers.json",
}
MAX_FILES = 40
MAX_BYTES = 200_000
REDACTIONS = [
    (re.compile(r"(sk-[A-Za-z0-9_-]{8,})"), "sk-***redacted***"),
    (re.compile(r"(ghp_[A-Za-z0-9]{8,})"), "ghp_***redacted***"),
    (re.compile(r"(AKIA[0-9A-Z]{8,})"), "AKIA***redacted***"),
    (re.compile(r"(xox[baprs]-[A-Za-z0-9-]{8,})"), "xox***redacted***"),
    (re.compile(r"(postgres(?:ql)?://[^:\s]+:)([^@\s]+)(@)", re.IGNORECASE), r"\1***\3"),
]
SEVERITY_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
}
GRADE_ORDER = "ABCDF"


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# scanning
# ---------------------------------------------------------------------------


@dataclass
class AuditResult:
    client: str
    prepared_by: str
    generated_at: str
    files: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    grade: str = "A"
    score: int = 0
    policy_yaml: str = ""
    skipped: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        return {
            "client": self.client,
            "prepared_by": self.prepared_by,
            "generated_at": self.generated_at,
            "grade": self.grade,
            "score": self.score,
            "counts": counts,
            "total_findings": len(self.findings),
            "files": [{"path": item["path"], "kind": item["kind"], "grade": item["grade"]} for item in self.files],
            "skipped": self.skipped,
        }


def _candidate_files(repo: Path) -> tuple[list[Path], list[Path]]:
    mcp: list[Path] = []
    python: list[Path] = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "node_modules" in path.parts:
            continue
        if path.stat().st_size > MAX_BYTES:
            continue
        if path.name.lower() in MCP_NAMES:
            mcp.append(path)
        elif path.suffix == ".py":
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"@(?:tool|function_tool|mcp\.tool|app\.tool)\b", text) or re.search(
                r"\b(?:subprocess|os\.system|eval|exec|pickle|shutil\.rmtree)\b", text
            ):
                python.append(path)
    return mcp[:MAX_FILES], python[:MAX_FILES]


def _collect(result: AuditResult, path: Path, kind: str, text: str) -> None:
    try:
        scan_result = scan(kind, text, subject=f"{result.client}:{path.name}")
    except ScanInputError as exc:
        result.skipped.append(f"{path.name}: {exc}")
        return
    result.files.append(
        {
            "path": str(path),
            "name": path.name,
            "kind": kind,
            "grade": scan_result.grade,
            "score": scan_result.score,
            "findings": len(scan_result.findings),
            "policy_yaml": redact(scan_result.policy_yaml),
        }
    )
    for finding in scan_result.findings:
        result.findings.append(
            {
                "id": finding.id,
                "severity": finding.severity,
                "title": finding.title,
                "detail": redact(finding.detail),
                "evidence": redact(finding.evidence),
                "remediation": finding.remediation,
                "source": path.name,
            }
        )


def audit_paths(paths: list[Path], client: str, prepared_by: str) -> AuditResult:
    result = AuditResult(client=client, prepared_by=prepared_by, generated_at=now_iso())
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        lower = path.name.lower()
        if lower in MCP_NAMES or path.suffix.lower() == ".json":
            _collect(result, path, "mcp", text)
        elif path.suffix == ".py":
            _collect(result, path, "python", text)
        else:
            kind = "mcp" if text.lstrip().startswith("{") and ("mcpServers" in text or '"servers"' in text) else "python"
            _collect(result, path, kind, text)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.findings.sort(key=lambda item: (order.get(item["severity"], 9), item["id"]))
    if result.files:
        result.grade = max((item["grade"] for item in result.files), key=lambda grade: GRADE_ORDER.index(grade))
        result.score = max(item["score"] for item in result.files)
        worst = max(result.files, key=lambda item: item["score"])
        result.policy_yaml = worst["policy_yaml"]
    return result


# ---------------------------------------------------------------------------
# signing
# ---------------------------------------------------------------------------


def load_or_create_key(path: Path) -> tuple[bytes, bytes]:
    if path.exists():
        private_pem = path.read_bytes()
        public_pem = signing.private_key_from_pem(private_pem).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem
    private_pem, public_pem = signing.generate_keypair_pem()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_pem)
    return private_pem, public_pem


def sign_result(result: AuditResult, private_pem: bytes, public_pem: bytes) -> dict[str, Any]:
    payload = {
        "client": result.client,
        "generated_at": result.generated_at,
        "grade": result.grade,
        "score": result.score,
        "findings": [
            {k: finding[k] for k in ("id", "severity", "title", "evidence", "source")}
            for finding in result.findings
        ],
        "files": [{"path": item["path"], "kind": item["kind"], "grade": item["grade"]} for item in result.files],
    }
    digest = signing.sha256_hex(signing.canonical_bytes(payload))
    signature = signing.sign_hex(private_pem, signing.canonical_bytes(payload))
    fingerprint = signing.public_key_fingerprint(public_pem)
    return {
        "digest": digest,
        "signature": signature,
        "public_key_pem": public_pem.decode("utf-8"),
        "fingerprint": fingerprint,
        "signed_at": now_iso(),
    }


def verify_report(report: dict[str, Any], public_pem: bytes) -> bool:
    payload = {
        "client": report["result"]["client"],
        "generated_at": report["result"]["generated_at"],
        "grade": report["result"]["grade"],
        "score": report["result"]["score"],
        "findings": [
            {k: finding[k] for k in ("id", "severity", "title", "evidence", "source")}
            for finding in report["result"]["findings"]
        ],
        "files": [
            {"path": item["path"], "kind": item["kind"], "grade": item["grade"]}
            for item in report["result"]["files"]
        ],
    }
    expected = signing.sha256_hex(signing.canonical_bytes(payload))
    return expected == report["signature"]["digest"] and signing.verify_hex(
        public_pem, signing.canonical_bytes(payload), report["signature"]["signature"]
    )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def render_markdown(result: AuditResult, signature: dict[str, Any]) -> str:
    counts = result.summary()["counts"]
    lines = [
        f"# AgentProof 安全审计报告 — {result.client}",
        "",
        f"- 客户：{result.client}",
        f"- 出具方：{result.prepared_by}",
        f"- 生成时间：{result.generated_at}",
        f"- 总体评级：**{result.grade}**（风险分 {result.score}/100）",
        f"- 命中问题：{len(result.findings)} 项（致命 {counts['critical']} / 高危 {counts['high']} / 中危 {counts['medium']} / 低危 {counts['low']}）",
        "",
        "> 静态分析，不执行目标代码、不发起网络请求。发现是风险线索，不是漏洞利用证明。",
        "",
        "## 扫描范围",
        "",
        "| 文件 | 类型 | 评级 | 命中 |",
        "|---|---|---|---|",
    ]
    for item in result.files:
        lines.append(f"| `{item['name']}` | {item['kind']} | **{item['grade']}** | {item['findings']} |")
    if result.skipped:
        lines += ["", "未能扫描：", ""]
        lines += [f"- {item}" for item in result.skipped]
    lines += ["", "## 发现", ""]
    for index, finding in enumerate(result.findings, start=1):
        lines += [
            f"### {index}. [{SEVERITY_LABEL.get(finding['severity'], finding['severity'])}] {finding['title']}",
            "",
            f"- 规则：`{finding['id']}` · 来源：`{finding['source']}`",
            f"- 说明：{finding['detail']}",
            f"- 证据：`{finding['evidence']}`",
            f"- 修复：{finding['remediation']}",
            "",
        ]
    if result.policy_yaml:
        lines += ["## 可直接落地的默认拒绝策略", "", "```yaml", result.policy_yaml.split("\n# audit")[0], "```", ""]
    lines += [
        "## 报告完整性",
        "",
        f"- 报告摘要（SHA-256）：`{signature['digest']}`",
        f"- Ed25519 签名：`{signature['signature']}`",
        f"- 公钥指纹：`{signature['fingerprint']}`",
        "- 公钥：",
        "",
        "```pem",
        signature["public_key_pem"].strip(),
        "```",
        "",
        "校验：`python tools/audit_report.py verify --report report.json --public-key public-key.pem`",
        "",
        "## 边界",
        "",
        "- 本报告是静态风险线索与修复建议，不是漏洞利用证明、合规认证或法律意见。",
        "- 只覆盖被扫描到的文件；未接入扫描范围的代码/运行时不在结论内。",
        "- 如需复测，请使用同一份报告摘要作为对照基线。",
        "",
    ]
    return "\n".join(lines)


def render_html(result: AuditResult, signature: dict[str, Any]) -> str:
    counts = result.summary()["counts"]
    grade_color = {"A": "#34d399", "B": "#22d3ee", "C": "#fbbf24", "D": "#fb923c", "F": "#f87171"}.get(result.grade, "#94a3b8")
    finding_html = []
    for index, finding in enumerate(result.findings, start=1):
        color = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#60a5fa"}.get(finding["severity"], "#94a3b8")
        finding_html.append(
            f"""
            <article class="finding" style="--sev:{color}">
              <header><span class="sev">{_esc(SEVERITY_LABEL.get(finding['severity'], finding['severity']))}</span>
              <h3>{index}. {_esc(finding['title'])}</h3></header>
              <p class="meta">规则 <code>{_esc(finding['id'])}</code> · 来源 <code>{_esc(finding['source'])}</code></p>
              <p>{_esc(finding['detail'])}</p>
              <pre class="evidence">{_esc(finding['evidence'])}</pre>
              <p class="fix"><b>修复：</b>{_esc(finding['remediation'])}</p>
            </article>
            """
        )
    file_rows = "".join(
        f"<tr><td><code>{_esc(item['name'])}</code></td><td>{_esc(item['kind'])}</td>"
        f"<td><b>{_esc(item['grade'])}</b></td><td>{item['findings']}</td></tr>"
        for item in result.files
    )
    policy_block = (
        f'<section><h2>可直接落地的默认拒绝策略</h2><pre class="code">{_esc(result.policy_yaml)}</pre></section>'
        if result.policy_yaml else ""
    )
    skipped_block = ""
    if result.skipped:
        skipped_block = "<section><h2>未能扫描</h2><ul>" + "".join(
            f"<li>{_esc(item)}</li>" for item in result.skipped
        ) + "</ul></section>"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentProof 安全审计报告 — {_esc(result.client)}</title>
<style>
  :root {{ --bg:#070b14; --panel:#101828; --line:rgba(255,255,255,.1); --text:#e9edf7; --muted:#9aa6bf; --accent:#7c5cff; --accent2:#22d3ee; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.7 "Segoe UI", "Noto Sans SC", system-ui, sans-serif; }}
  .page {{ max-width:900px; margin:0 auto; padding:48px 32px 80px; }}
  header.cover {{ border:1px solid var(--line); border-radius:20px; padding:36px; background:linear-gradient(160deg,#141a2c,#0b1020); margin-bottom:28px; }}
  .brand {{ color:var(--accent2); font-weight:700; letter-spacing:.08em; text-transform:uppercase; font-size:12px; }}
  h1 {{ font-size:34px; letter-spacing:-.02em; margin:10px 0 6px; }}
  .sub {{ color:var(--muted); margin:0 0 26px; }}
  .cover-grid {{ display:flex; gap:36px; flex-wrap:wrap; align-items:center; }}
  .grade {{ width:120px; height:120px; border-radius:50%; display:grid; place-items:center;
            background:radial-gradient(circle at 50% 50%, #0b1020 56%, transparent 58%), conic-gradient({grade_color} 0 .78turn, rgba(255,255,255,.08) .78turn 1turn); }}
  .grade b {{ font-size:44px; color:{grade_color}; }}
  .grade small {{ display:block; font-size:10px; color:var(--muted); text-align:center; letter-spacing:.1em; }}
  .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; flex:1; min-width:280px; }}
  .stat {{ border:1px solid var(--line); border-radius:12px; padding:12px; background:rgba(255,255,255,.03); }}
  .stat b {{ display:block; font-size:20px; }}
  .stat span {{ color:var(--muted); font-size:12px; }}
  h2 {{ font-size:22px; margin:36px 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
  th, td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }}
  .finding {{ border:1px solid var(--line); border-left:3px solid var(--sev); border-radius:12px; padding:16px 18px; margin:12px 0; background:rgba(255,255,255,.025); }}
  .finding header {{ display:flex; align-items:baseline; gap:10px; }}
  .finding h3 {{ font-size:15.5px; margin:0; }}
  .sev {{ font-size:10px; font-weight:700; letter-spacing:.08em; color:var(--sev); background:color-mix(in srgb, var(--sev) 16%, transparent); padding:2px 7px; border-radius:5px; }}
  .meta {{ color:var(--muted); font-size:12px; margin:6px 0 8px; }}
  .evidence, .code {{ background:#04070d; border:1px solid var(--line); border-radius:9px; padding:12px; overflow:auto; font:12px/1.6 ui-monospace, Consolas, monospace; color:#a9b8d8; }}
  .fix {{ margin:8px 0 0; font-size:13.5px; }}
  .integrity {{ border:1px dashed rgba(52,211,153,.4); background:rgba(52,211,153,.06); border-radius:12px; padding:16px; font-size:13px; }}
  .integrity code {{ word-break:break-all; }}
  ul {{ color:var(--muted); }}
  footer {{ margin-top:44px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); padding-top:16px; }}
  @media print {{
    body {{ background:#fff; color:#111; }}
    .page {{ max-width:none; padding:0; }}
    header.cover, .finding, .integrity, .stat {{ background:#fff; border-color:#ccc; }}
    .sub, .meta, .stat span, ul, footer {{ color:#444; }}
    h1, h2, h3, b, .grade b {{ color:#111 !important; }}
    .evidence, .code {{ background:#f6f6f6; color:#111; border-color:#ddd; }}
  }}
</style>
</head>
<body>
<div class="page">
  <header class="cover">
    <div class="brand">AgentProof.cloud · Security Audit</div>
    <h1>Agent / MCP 安全审计报告</h1>
    <p class="sub">客户：{_esc(result.client)} · 出具方：{_esc(result.prepared_by)} · {_esc(result.generated_at)}</p>
    <div class="cover-grid">
      <div class="grade"><div><b>{_esc(result.grade)}</b><small>风险评级</small></div></div>
      <div class="stats">
        <div class="stat"><b>{counts['critical']}</b><span>致命</span></div>
        <div class="stat"><b>{counts['high']}</b><span>高危</span></div>
        <div class="stat"><b>{counts['medium']}</b><span>中危</span></div>
        <div class="stat"><b>{counts['low']}</b><span>低危</span></div>
      </div>
    </div>
  </header>

  <section>
    <h2>扫描范围与方法</h2>
    <p>本报告基于静态分析：只读取被扫描文件，不执行目标代码、不安装依赖、不发起网络请求。
    证据中的密钥与口令已在渲染前脱敏。未扫描到的文件不在结论范围内。</p>
    <table><thead><tr><th>文件</th><th>类型</th><th>评级</th><th>命中</th></tr></thead>
    <tbody>{file_rows or '<tr><td colspan="4">没有发现可扫描的 MCP 配置或 Agent 工具代码</td></tr>'}</tbody></table>
  </section>

  {skipped_block}

  <section>
    <h2>发现（{len(result.findings)} 项）</h2>
    {''.join(finding_html) or '<p>未命中扫描规则。继续保持默认拒绝与最小权限。</p>'}
  </section>

  {policy_block}

  <section>
    <h2>报告完整性</h2>
    <div class="integrity">
      <p>报告摘要（SHA-256）：<br><code>{_esc(signature['digest'])}</code></p>
      <p>Ed25519 签名：<br><code>{_esc(signature['signature'])}</code></p>
      <p>公钥指纹：<br><code>{_esc(signature['fingerprint'])}</code></p>
      <p>公钥：<br><code style="white-space:pre-wrap">{_esc(signature['public_key_pem'].strip())}</code></p>
      <p>校验：<code>python tools/audit_report.py verify --report report.json --public-key public-key.pem</code></p>
    </div>
  </section>

  <section>
    <h2>边界</h2>
    <ul>
      <li>本报告是静态风险线索与修复建议，不是漏洞利用证明、合规认证或法律意见。</li>
      <li>只覆盖被扫描到的文件；运行时行为与被绕过路径不在结论内。</li>
      <li>复测请以本报告摘要作为对照基线；摘要或签名不一致即视为报告被改动。</li>
    </ul>
  </section>

  <footer>AgentProof.cloud · 证据，而不是声称 · 本报告由静态扫描 + 人工复核生成</footer>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a signed, client-ready AgentProof audit report.")
    sub = parser.add_subparsers(dest="command")
    verify_parser = sub.add_parser("verify", help="verify a report.json against a public key")
    verify_parser.add_argument("--report", required=True)
    verify_parser.add_argument("--public-key", required=True)

    parser.add_argument("--repo", help="scan every mcp config and agent tool file under this directory")
    parser.add_argument("--file", action="append", default=[], help="scan a specific file (repeatable)")
    parser.add_argument("--kind", choices=["mcp", "python"], help="force the input kind for --file")
    parser.add_argument("--client", default="Client", help="client/company name on the cover")
    parser.add_argument("--prepared-by", default="AgentProof.cloud", help="who issues the report")
    parser.add_argument("--out", default="audit", help="output directory")
    parser.add_argument("--key", default=str(ROOT / ".tmp" / "audit-signing-key.pem"), help="Ed25519 signing key path")
    args = parser.parse_args(argv)

    if args.command == "verify":
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        public_pem = Path(args.public_key).read_bytes()
        ok = verify_report(report, public_pem)
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    paths: list[Path] = []
    if args.repo:
        repo = Path(args.repo)
        if not repo.is_dir():
            print(f"not a directory: {repo}", file=sys.stderr)
            return 2
        mcp, python = _candidate_files(repo)
        paths.extend(mcp + python)
    for item in args.file:
        path = Path(item)
        if not path.exists():
            print(f"file not found: {path}", file=sys.stderr)
            return 2
        paths.append(path)
    if not paths:
        print("nothing to scan: pass --repo or --file", file=sys.stderr)
        return 2

    result = audit_paths(paths, args.client, args.prepared_by)
    if args.kind and len(paths) == 1:
        # re-run a single forced-kind input
        text = paths[0].read_text(encoding="utf-8", errors="replace")
        result = AuditResult(client=args.client, prepared_by=args.prepared_by, generated_at=now_iso())
        _collect(result, paths[0], args.kind, text)
        if result.files:
            result.grade = result.files[0]["grade"]
            result.score = result.files[0]["score"]
            result.policy_yaml = result.files[0]["policy_yaml"]
        result.findings.sort(key=lambda item: item["id"])

    key_path = Path(args.key)
    private_pem, public_pem = load_or_create_key(key_path)
    signature = sign_result(result, private_pem, public_pem)
    report = {"result": result.__dict__, "signature": signature}

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = out_dir / "report.json"
    report_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "report.html").write_text(render_html(result, signature), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(result, signature), encoding="utf-8")
    (out_dir / "public-key.pem").write_bytes(public_pem)

    print(f"grade={result.grade} findings={len(result.findings)} files={len(result.files)}")
    print(f"wrote {out_dir / 'report.html'}, report.md, report.json, public-key.pem")
    print(f"digest={signature['digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

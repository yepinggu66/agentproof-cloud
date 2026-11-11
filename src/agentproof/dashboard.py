"""Render a chain as a single-file HTML dashboard.

Design constraints, in priority order:

1. **One file, zero external requests.** An auditor receives a file, not a
   deployment. No CDN, no font fetch, no analytics, no network at all. It
   opens from ``file://`` on a machine with no internet.
2. **The conclusion is visible in three seconds.** Integrity status, decision
   counts, what was denied. An executive should not have to read anything to
   get the answer.
3. **The browser re-verifies independently.** The page recomputes every hash
   from scratch. The green banner is not a claim by the tool; it is a result
   the auditor's own browser produced.
4. **Printable.** A compliance officer will print it or attach it to a
   ticket. The print stylesheet removes the chrome and keeps the evidence.

The visual language is deliberately quiet: this is a document that has to
survive being forwarded to a regulator.
"""

from __future__ import annotations

import base64
import datetime as _dt
import html
import json
from pathlib import Path
from typing import Any

from .core.canonical import canonical_json
from .dashboard_js import JS_VERIFIER

__all__ = ["render_dashboard", "build_dashboard_data"]

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-2: #fbfbfc;
  --border: #e3e5e9;
  --border-strong: #d0d3d9;
  --text: #1c1e23;
  --text-2: #5c6270;
  --text-3: #8b909c;
  --accent: #4a55c7;
  --accent-soft: #eef0fb;
  --allow: #1a7f52;
  --allow-soft: #e6f4ec;
  --deny: #b4272a;
  --deny-soft: #fceaea;
  --halt: #96660a;
  --halt-soft: #fdf3e0;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", "PingFang SC",
          "Microsoft YaHei", Roboto, Helvetica, Arial, sans-serif;
  --radius: 10px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a;
    --surface: #1c1f25;
    --surface-2: #21242b;
    --border: #2e323a;
    --border-strong: #3d434e;
    --text: #e8eaed;
    --text-2: #a8aeb9;
    --text-3: #767c88;
    --accent: #8f9bff;
    --accent-soft: #23273a;
    --allow: #52c58c;
    --allow-soft: #16301f;
    --deny: #f28b82;
    --deny-soft: #35191a;
    --halt: #e0b354;
    --halt-soft: #33260f;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.6;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }

header.top {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 24px; flex-wrap: wrap; margin-bottom: 28px;
}
.brand { display: flex; align-items: center; gap: 11px; }
.mark {
  width: 30px; height: 30px; border-radius: 8px; flex: none;
  background: var(--accent); color: #fff;
  display: grid; place-items: center; font-weight: 700; font-size: 14px;
}
.brand h1 { margin: 0; font-size: 16px; font-weight: 600; letter-spacing: -0.01em; }
.brand p { margin: 0; font-size: 12px; color: var(--text-3); }
.head-meta { text-align: right; font-size: 12px; color: var(--text-3); }
.head-meta div { margin-top: 2px; }
.head-meta code { font-family: var(--mono); font-size: 11px; color: var(--text-2); }

.verdict {
  border: 1px solid var(--border); border-radius: var(--radius);
  background: var(--surface); padding: 20px 22px; margin-bottom: 22px;
  display: flex; gap: 18px; align-items: flex-start;
}
.verdict.pass { border-color: color-mix(in srgb, var(--allow) 40%, var(--border)); }
.verdict.fail { border-color: color-mix(in srgb, var(--deny) 45%, var(--border)); }
.verdict.unknown { border-color: color-mix(in srgb, var(--halt) 40%, var(--border)); }
.seal-dot {
  width: 44px; height: 44px; border-radius: 50%; flex: none;
  display: grid; place-items: center; font-size: 21px; font-weight: 700;
}
.verdict.pass .seal-dot { background: var(--allow-soft); color: var(--allow); }
.verdict.fail .seal-dot { background: var(--deny-soft); color: var(--deny); }
.verdict.unknown .seal-dot { background: var(--halt-soft); color: var(--halt); }
.verdict h2 { margin: 0 0 3px; font-size: 17px; font-weight: 600; letter-spacing: -0.01em; }
.verdict p { margin: 0; font-size: 13px; color: var(--text-2); }
.verdict .detail {
  margin-top: 9px; padding-top: 9px; border-top: 1px solid var(--border);
  font-size: 12px; color: var(--text-3);
}
.verdict .detail code { font-family: var(--mono); font-size: 11px; }

.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(132px, 1fr)); gap: 12px; margin-bottom: 26px; }
.metric { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; }
.metric .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-3); }
.metric .value { font-size: 25px; font-weight: 600; letter-spacing: -0.02em; margin-top: 3px; line-height: 1.15; }
.metric .value.allow { color: var(--allow); }
.metric .value.deny { color: var(--deny); }
.metric .value.halt { color: var(--halt); }
.metric .sub { font-size: 11px; color: var(--text-3); margin-top: 2px; }

section { margin-bottom: 28px; }
section > h3 {
  margin: 0 0 11px; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-3);
}
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th {
  text-align: left; font-weight: 500; font-size: 11px; letter-spacing: 0.05em;
  text-transform: uppercase; color: var(--text-3);
  padding: 9px 14px; border-bottom: 1px solid var(--border); background: var(--surface-2);
  white-space: nowrap;
}
tbody td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-2); }
td.seq { font-family: var(--mono); font-size: 12px; color: var(--text-3); width: 46px; }
td.hash { font-family: var(--mono); font-size: 11px; color: var(--text-3); }
td.ts { font-family: var(--mono); font-size: 11px; color: var(--text-3); white-space: nowrap; }
td.reason { color: var(--text-2); }

.badge {
  display: inline-block; padding: 2px 8px; border-radius: 5px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.03em; white-space: nowrap;
}
.badge.allow { background: var(--allow-soft); color: var(--allow); }
.badge.deny { background: var(--deny-soft); color: var(--deny); }
.badge.halt { background: var(--halt-soft); color: var(--halt); }
.badge.plain { background: var(--surface-2); color: var(--text-2); border: 1px solid var(--border); }
.action { font-family: var(--mono); font-size: 12px; }

ul.plain { margin: 0; padding-left: 18px; }
ul.plain li { margin: 4px 0; color: var(--text-2); font-size: 13px; }
ul.plain li code, .mono { font-family: var(--mono); font-size: 11.5px; }

.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 760px) { .grid2 { grid-template-columns: 1fr; } }

.note {
  background: var(--surface-2); border: 1px solid var(--border);
  border-left: 3px solid var(--border-strong);
  border-radius: 0 var(--radius) var(--radius) 0; padding: 13px 16px;
  font-size: 12.5px; color: var(--text-2);
}
.note strong { color: var(--text); font-weight: 600; }
.note.limitation { border-left-color: var(--halt); }

.verifybar {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 11px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border);
  font-size: 12px; color: var(--text-2);
}
button.run {
  font: inherit; font-size: 12px; font-weight: 500;
  background: var(--accent); color: #fff; border: none;
  padding: 6px 13px; border-radius: 6px; cursor: pointer;
}
button.run:hover { filter: brightness(1.08); }
button.run:active { transform: translateY(0.5px); }
.verifybar .status { font-family: var(--mono); font-size: 11.5px; }
.verifybar .status.ok { color: var(--allow); }
.verifybar .status.bad { color: var(--deny); }
.spin { display: inline-block; animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; } }

.problems { padding: 12px 16px; font-size: 12.5px; }
.problems li { color: var(--deny); margin: 3px 0; }

footer {
  margin-top: 34px; padding-top: 18px; border-top: 1px solid var(--border);
  font-size: 11.5px; color: var(--text-3);
}
footer p { margin: 4px 0; }
footer code { font-family: var(--mono); }

@media print {
  :root { --bg: #fff; --surface: #fff; --surface-2: #f7f7f8; --text: #000; --text-2: #333; --text-3: #666; --border: #ccc; }
  body { font-size: 11px; }
  .wrap { max-width: none; padding: 0; }
  button.run, .no-print { display: none !important; }
  section { break-inside: avoid; }
  .panel { border: 1px solid #ccc; }
  .verdict { border-width: 2px; }
  a[href]:after { content: ""; }
}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def build_dashboard_data(chain_data: dict[str, Any]) -> dict[str, Any]:
    """Prepare the JSON payload embedded in the dashboard.

    Each record gains a ``canonical_b64`` field: the exact bytes the Python
    side hashed, base64-encoded. The browser recomputes its own canonical
    form and compares, which turns the page into a genuine cross-implementation
    check rather than a self-assertion.
    """
    from .core.canonical import canonical_bytes
    from .core.receipt import Receipt

    records = []
    for raw in chain_data.get("records", []):
        receipt = Receipt.from_dict(raw)
        record = dict(raw)
        record["canonical_b64"] = base64.b64encode(canonical_bytes(receipt.body())).decode(
            "ascii"
        )
        records.append(record)

    payload = dict(chain_data)
    payload["records"] = records
    payload["_meta"] = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "tool": "agentproof",
    }
    return payload


def render_dashboard(
    chain_data: dict[str, Any],
    *,
    subject: str = "",
    verification: dict[str, Any] | None = None,
    aibom: dict[str, Any] | None = None,
    title: str = "",
    limitations: list[str] | None = None,
    control_map: dict[str, list[str]] | None = None,
) -> str:
    """Render the dashboard as a self-contained HTML document.

    ``verification`` is the result of :func:`agentproof.core.verify.verify_receipts`
    in its ``to_dict()`` form. ``limitations`` and ``control_map`` are
    accepted separately so a caller does not have to reshape the pack.
    """
    payload = build_dashboard_data(chain_data)
    records = payload.get("records", [])
    seal = payload.get("seal")
    meta = payload["_meta"]

    if subject:
        payload["subject"] = subject

    # --- counts -----------------------------------------------------------
    by_decision: dict[str, int] = {}
    by_action: dict[str, int] = {}
    actors: set[str] = set()
    for record in records:
        decision = str(record.get("decision", ""))
        by_decision[decision] = by_decision.get(decision, 0) + 1
        action = str(record.get("action", ""))
        by_action[action] = by_action.get(action, 0) + 1
        if record.get("actor"):
            actors.add(str(record["actor"]))

    total = len(records)
    n_allow = by_decision.get("ALLOW", 0)
    n_deny = by_decision.get("DENY", 0)
    n_halt = by_decision.get("HALT", 0)

    # --- verdict ----------------------------------------------------------
    server_ok = bool((verification or {}).get("ok"))
    server_problems = list((verification or {}).get("problems") or [])
    if verification is None:
        verdict_class, verdict_title, verdict_text = "unknown", "Integrity not yet checked", \
            "Run the in-page verification to recompute the chain independently."
    elif server_ok:
        verdict_class, verdict_title = "pass", "Integrity verified"
        verdict_text = (
            f"All {total} records hash correctly, the chain links without gaps, "
            "and the seal matches the chain."
        )
    else:
        verdict_class, verdict_title = "fail", "Integrity check failed"
        verdict_text = (
            f"{len(server_problems)} problem(s) were found. The records below do "
            "not form a consistent, unaltered chain."
        )

    seal_state = "absent"
    if seal:
        seal_state = "matches" if server_ok else "does not match"

    # --- rows -------------------------------------------------------------
    rows_html = []
    for record in records:
        decision = str(record.get("decision", ""))
        klass = {"ALLOW": "allow", "DENY": "deny", "HALT": "halt"}.get(decision, "plain")
        rows_html.append(
            f"""      <tr>
        <td class="seq">{_esc(record.get('seq'))}</td>
        <td class="ts">{_esc(record.get('issued_at'))}</td>
        <td class="action">{_esc(record.get('action'))}</td>
        <td><span class="badge {klass}">{_esc(decision)}</span></td>
        <td class="reason">{_esc(record.get('reason'))}</td>
        <td class="hash">{_esc(str(record.get('record_hash', ''))[:16])}…</td>
      </tr>"""
        )

    action_rows = "\n".join(
        f"""      <tr>
        <td class="action">{_esc(action)}</td>
        <td style="text-align:right">{count}</td>
      </tr>"""
        for action, count in sorted(by_action.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    problems_html = ""
    if server_problems:
        items = "\n".join(f"      <li>{_esc(p)}</li>" for p in server_problems)
        problems_html = f"""    <ul class="problems">
{items}
    </ul>"""

    control_html = ""
    if control_map:
        blocks = []
        for name, references in control_map.items():
            refs = "\n".join(f"        <li>{_esc(r)}</li>" for r in references)
            blocks.append(
                f"""      <div>
        <p style="margin:0 0 6px;font-family:var(--mono);font-size:12px">{_esc(name)}</p>
        <ul class="plain">
{refs}
        </ul>
      </div>"""
            )
        control_html = f"""  <section>
    <h3>Control mapping</h3>
    <div class="panel grid2" style="padding:16px">
{chr(10).join(blocks)}
    </div>
  </section>"""

    aibom_html = ""
    if aibom:
        tool_rows = "\n".join(
            f"""        <tr>
          <td class="action">{_esc(t.get('name'))}</td>
          <td style="text-align:right">{_esc(t.get('call_count'))}</td>
          <td class="reason">{_esc(', '.join(t.get('agents', [])))}</td>
        </tr>"""
            for t in aibom.get("tools", [])
        )
        aibom_html = f"""  <section>
    <h3>AI Bill of Materials</h3>
    <div class="panel">
      <table>
        <thead><tr><th>Tool</th><th style="text-align:right">Calls</th><th>Used by</th></tr></thead>
        <tbody>
{tool_rows}
        </tbody>
      </table>
    </div>
  </section>"""

    limitations = list(limitations or [])
    limitation_items = "\n".join(f"      <li>{_esc(l)}</li>" for l in limitations)
    limitation_html = (
        f"""  <section>
    <h3>Limitations</h3>
    <div class="note limitation">
      <p style="margin:0 0 6px"><strong>What this document does not establish.</strong></p>
      <ul class="plain" style="margin:0">
{limitation_items}
      </ul>
    </div>
  </section>"""
        if limitation_items
        else ""
    )

    data_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    # Escape the HTML-significant characters for embedding inside a <script>
    # element. Escaping only "</" is not enough: the HTML parser has a
    # "script data double escaped" state, where a "</script>" following a
    # "<!--<script" sequence does NOT close the element. Escaping every "<",
    # ">" and "&" removes that class of problem entirely. JSON unescapes
    # \u003c back to "<", so the payload is unchanged.
    data_json = (
        data_json.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )

    chain_id = str(chain_data.get("chain_id", ""))
    final_hash = str(records[-1].get("record_hash", "")) if records else ""
    display_subject = subject or str(chain_data.get("subject") or "Untitled subject")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{_esc(title or display_subject)} — agentproof 证据仪表盘</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="brand">
    <div class="mark">A</div>
    <div>
      <h1>agentproof 证据仪表盘</h1>
      <p>{_esc(display_subject)}</p>
    </div>
  </div>
  <div class="head-meta">
    <div>Chain ID <code>{_esc(chain_id)}</code></div>
    <div>Generated <code>{_esc(meta['generated_at'])}</code></div>
    <div>Seal <code>{_esc(seal_state)}</code></div>
  </div>
</header>

<div class="verdict {verdict_class}">
  <div class="seal-dot">{'✓' if verdict_class == 'pass' else ('✕' if verdict_class == 'fail' else '?')}</div>
  <div style="flex:1;min-width:0">
    <h2>{_esc(verdict_title)}</h2>
    <p>{_esc(verdict_text)}</p>
    <div class="detail">
      最终哈希 <code>{_esc(final_hash[:32])}…</code>
    </div>
  </div>
</div>

<div class="metrics">
  <div class="metric">
    <div class="label">决策总数</div>
    <div class="value">{total}</div>
    <div class="sub">{len(by_action)} 个动作 · {len(actors)} 个执行方</div>
  </div>
  <div class="metric">
    <div class="label">允许</div>
    <div class="value allow">{n_allow}</div>
    <div class="sub">ALLOW</div>
  </div>
  <div class="metric">
    <div class="label">拒绝</div>
    <div class="value deny">{n_deny}</div>
    <div class="sub">DENY</div>
  </div>
  <div class="metric">
    <div class="label">暂停</div>
    <div class="value halt">{n_halt}</div>
    <div class="sub">HALT</div>
  </div>
</div>

<section>
  <h3>决策记录</h3>
  <div class="panel">
    <div class="verifybar">
      <button class="run" id="run-verify">在浏览器中独立复算</button>
      <span class="status" id="verify-status">尚未复算 — 页面只显示生成时的结果</span>
      <span class="no-print" style="margin-left:auto;color:var(--text-3)">
        复算使用页面内置的 SHA-256 与规范化实现，不发送任何网络请求
      </span>
    </div>
{problems_html}
    <table>
      <thead>
        <tr>
          <th>#</th><th>时间</th><th>动作</th><th>决策</th><th>理由</th><th>记录哈希</th>
        </tr>
      </thead>
      <tbody>
{chr(10).join(rows_html)}
      </tbody>
    </table>
  </div>
</section>

<section>
  <h3>动作分布</h3>
  <div class="panel">
    <table>
      <thead><tr><th>动作</th><th style="text-align:right">调用次数</th></tr></thead>
      <tbody>
{action_rows}
      </tbody>
    </table>
  </div>
</section>

{aibom_html}
{control_html}
{limitation_html}

<footer>
  <p>本文件由 <code>agentproof</code> 生成，是一个自包含的离线文档：不含外部脚本、字体或统计代码，打开时不产生任何网络请求。</p>
  <p>独立复算方式：用 <code>agentproof verify &lt;chain.json&gt; --seal &lt;seal.json&gt;</code>，或直接把 <code>chain.json</code> 与 <code>seal.json</code> 交给任何能验证 Ed25519 签名与 SHA-256 的工具。</p>
  <p>签名证明决策由持钥方签发且此后未被篡改；不证明决策本身正确。合规判定属于法务或公告机构，不属于本工具。</p>
</footer>

</div>

<script id="payload" type="application/json">{data_json}</script>
<script>
{JS_VERIFIER}
(function () {{
  var data = JSON.parse(document.getElementById('payload').textContent);
  var statusEl = document.getElementById('verify-status');
  var btn = document.getElementById('run-verify');

  btn.addEventListener('click', function () {{
    btn.disabled = true;
    statusEl.className = 'status';
    statusEl.innerHTML = '<span class="spin">◌</span> 复算中…';
    setTimeout(function () {{
      var result;
      try {{
        result = verifyChain(data);
      }} catch (err) {{
        statusEl.className = 'status bad';
        statusEl.textContent = '复算出错: ' + err.message;
        btn.disabled = false;
        return;
      }}
      if (result.ok) {{
        statusEl.className = 'status ok';
        statusEl.textContent = '✓ 复算通过 — ' + result.records + ' 条记录哈希正确、链无断裂、封存一致';
      }} else {{
        statusEl.className = 'status bad';
        statusEl.textContent = '✕ 复算失败 — ' + result.problems.length + ' 项问题';
      }}
      btn.disabled = false;
    }}, 30);
  }});
}})();
</script>
</body>
</html>
"""

"""Self-contained Interactive Web SaaS Console for AgentProof Cloud (Bilingual CN/EN)."""

from __future__ import annotations

import html


def render_cloud_console_html(
    *,
    witness_pubkey: str,
    demo_api_key: str,
    demo_tenant_id: str,
) -> str:
    w_pub = html.escape(witness_pubkey)
    d_key = html.escape(demo_api_key)
    d_tnt = html.escape(demo_tenant_id)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AgentProof Cloud — 企业级 AI 动作防越权门禁与密码学合规公证 SaaS 系统</title>
<style>
  :root {{
    --bg: #0b0f17;
    --panel: #131b2e;
    --panel-border: #23304d;
    --text: #e6edf7;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --red: #ef4444;
    --amber: #f59e0b;
    --purple: #a855f7;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Microsoft YaHei", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  header {{
    border-bottom: 1px solid var(--panel-border);
    padding: 16px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #0e1525;
    flex-wrap: wrap;
    gap: 12px;
  }}
  .brand {{
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 700;
    font-size: 18px;
  }}
  .badge {{
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 999px;
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent);
    border: 1px solid rgba(56, 189, 248, 0.35);
    font-weight: 600;
  }}
  main {{ max-width: 1320px; margin: 0 auto; padding: 20px 28px 60px; }}
  .explainer {{
    background: linear-gradient(90deg, rgba(56,189,248,0.12), rgba(168,85,247,0.12));
    border: 1px solid rgba(56,189,248,0.35);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 20px;
    font-size: 14px;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin-bottom: 22px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    padding: 18px 20px;
  }}
  .kpi-label {{ font-size: 12px; color: var(--muted); font-weight: 600; }}
  .kpi-val {{ font-size: 26px; font-weight: 700; margin-top: 6px; }}
  .kpi-sub {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  .grid-2 {{
    display: grid;
    grid-template-columns: 1.9fr 1.1fr;
    gap: 20px;
    margin-bottom: 24px;
  }}
  h2 {{ font-size: 16px; margin: 0 0 12px; display: flex; align-items: center; justify-content: space-between; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--panel-border); }}
  th {{ color: var(--muted); font-weight: 600; font-size: 12px; }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    background: rgba(255,255,255,0.07);
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .pill {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
  }}
  .pill-ALLOW {{ background: rgba(34,197,94,0.18); color: var(--green); }}
  .pill-DENY {{ background: rgba(239,68,68,0.18); color: var(--red); }}
  .pill-HALT {{ background: rgba(245,158,11,0.18); color: var(--amber); }}
  button {{
    background: var(--accent);
    color: #06101e;
    border: none;
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 600;
    cursor: pointer;
    font-size: 13px;
    transition: opacity 0.15s;
  }}
  button:hover {{ opacity: 0.9; }}
  button.danger {{ background: var(--red); color: #fff; }}
  button.warn {{ background: var(--amber); color: #06101e; }}
  button.secondary {{
    background: transparent;
    color: var(--text);
    border: 1px solid var(--panel-border);
  }}
  input, select {{
    background: #0b0f17;
    color: var(--text);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 13px;
    width: 100%;
    margin-bottom: 10px;
  }}
  .sim-bar {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 14px;
    padding: 12px;
    background: rgba(255,255,255,0.03);
    border: 1px dashed var(--panel-border);
    border-radius: 8px;
  }}
  .tier-box {{
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  #toast {{
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #1e293b;
    border: 2px solid var(--accent);
    padding: 14px 20px;
    border-radius: 8px;
    display: none;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    z-index: 999;
  }}
</style>
</head>
<body>
<header>
  <div class="brand">
    <span>🛡️ AgentProof Cloud</span>
    <span class="badge">真实验证代码系统（非提示词！）</span>
    <span class="badge">Ed25519 密码学双签公证引擎</span>
    <span class="badge">EU AI Act Art.26 / 劳合社 AIUC-1 核保</span>
  </div>
  <div style="font-size:12px;color:var(--muted);">
    云端独立见证公钥 (Cloud Witness PubKey): <code id="witness-pub">{w_pub[:24]}...</code>
  </div>
</header>

<main>
  <div class="explainer">
    <strong>💡 这是一个什么样的软件应用系统？（为什么资本愿意出 $5M–$30M 收购它？）</strong><br/>
    这不是提示词！这是一套用 Python + 密码学（Ed25519 数字签名 + SHA-256 防篡改哈希链 + SQLite/Postgres 多租户账本）开发的<strong>“企业 AI 动作黑匣子与合规公证 SaaS 平台”</strong>。<br/>
    当企业的 AI Agent 要执行“转账、删库、调接口、运行命令行”时，本系统在<strong>动作发生前 1 毫秒</strong>进行强制策略拦截，签发不可篡改的密码学收据，并实时同步到本云端进行<strong>第三方独立公证双签（Witness Counter-Sign）</strong>，供审计师（四大）和保险公司（劳合社 AI 责任险）核保验证！
  </div>

  <div class="kpi-grid">
    <div class="card">
      <div class="kpi-label">平台经常性年收入 (Platform ARR / 并购估值锚点)</div>
      <div class="kpi-val" id="kpi-arr" style="color:var(--green);">$19,188 ARR</div>
      <div class="kpi-sub" id="kpi-tenants">正在加载付费企业租户...</div>
    </div>
    <div class="card">
      <div class="kpi-label">当前企业租户 &amp; 订阅等级 (Active Tenant)</div>
      <div class="kpi-val" id="kpi-plan" style="color:var(--accent);">PRO ($99/月)</div>
      <div class="kpi-sub" id="kpi-org">租户 ID: {d_tnt}</div>
    </div>
    <div class="card">
      <div class="kpi-label">云端不可篡改公证收据数 (WORM Receipts)</div>
      <div class="kpi-val" id="kpi-quota">4 / 100,000</div>
      <div class="kpi-sub">100% 经云端独立私钥二次签名公证</div>
    </div>
    <div class="card">
      <div class="kpi-label">劳合社 AIUC-1 科技保险核保评分</div>
      <div class="kpi-val" style="color:var(--purple);">100 / 100</div>
      <div class="kpi-sub">TIER_1_PREFERRED (可获 -20% 保费折扣)</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>
        <span>⚡ 实时 AI 动作门禁拦截与云端密码学双签账本 (Live Ledger)</span>
        <button class="secondary" onclick="loadOverview()">↻ 刷新账本</button>
      </h2>

      <div class="sim-bar">
        <div style="width:100%;font-size:12px;color:var(--muted);margin-bottom:4px;">
          👇 <strong>点击下方按钮，亲自测试后端的实时策略拦截、Ed25519 签名与云端双签公证：</strong>
        </div>
        <button onclick="simulateAction('ledger.query', {{account:'acct_889'}})">
          ✅ 模拟合规动作：查询财务余额 (ALLOW)
        </button>
        <button class="warn" onclick="simulateAction('mcp.shell.exec', {{cmd:'curl http://169.254.169.254/meta-data'}})">
          ⚠️ 模拟高危 MCP 动作：调用 Shell 窃取内网凭证 (HALT 熔断)
        </button>
        <button class="danger" onclick="simulateAction('db.drop_customers', {{sql:'DROP TABLE customers'}})">
          🛑 模拟越权动作：AI 试图删除客户数据库 (DENY 阻断)
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>序号</th>
            <th>调用智能体 (Actor)</th>
            <th>请求动作 (Action)</th>
            <th>门禁决策</th>
            <th>拦截/放行原因</th>
            <th>本地哈希链指纹</th>
            <th>云端第三方公证双签</th>
          </tr>
        </thead>
        <tbody id="receipt-rows">
          <tr><td colspan="7" style="color:var(--muted);">正在加载密码学公证账本...</td></tr>
        </tbody>
      </table>
    </div>

    <div>
      <div class="card" style="margin-bottom:16px;">
        <h2>💰 SaaS 商业化订阅与变现闭环 (点击即刻体验升降级)</h2>
        <div class="tier-box">
          <div>
            <strong>Free 免费开源获客版</strong><br/>
            <span style="font-size:12px;color:var(--muted);">1,000 条公证收据/月 • $0/月</span>
          </div>
          <button class="secondary" onclick="upgradePlan('FREE')">切换免费版</button>
        </div>
        <div class="tier-box" style="border-color:var(--accent);">
          <div>
            <strong>Pro 合规团队版 (主力变现层)</strong><br/>
            <span style="font-size:12px;color:var(--muted);">100,000 条双签收据/月 • $99/月</span>
          </div>
          <button onclick="upgradePlan('PRO')">订阅 $99/月</button>
        </div>
        <div class="tier-box" style="border-color:var(--purple);">
          <div>
            <strong>Enterprise 企业与保险核保版</strong><br/>
            <span style="font-size:12px;color:var(--muted);">1,000 万条 WORM 收据 + AIUC-1 核保包 • $1,500/月</span>
          </div>
          <button onclick="upgradePlan('ENTERPRISE')">升级 $1,500/月</button>
        </div>
      </div>

      <div class="card">
        <h2>🏢 开通新企业客户租户 &amp; 签发生产 API Key</h2>
        <input id="new-org" placeholder="企业名称 (例如：字节跳动 AI 安全部 / Vanta Inc.)" />
        <input id="new-email" placeholder="安全负责人邮箱 (如 secops@company.com)" />
        <select id="new-plan">
          <option value="PRO">PRO 团队版 ($99/月 — 10万条配额)</option>
          <option value="ENTERPRISE">ENTERPRISE 企业版 ($1,500/月 — 1000万条配额)</option>
          <option value="FREE">FREE 免费版 ($0/月 — 1000条配额)</option>
        </select>
        <button style="width:100%;" onclick="createTenant()">立即开通企业租户并生成 API Key</button>
        <div id="api-key-box" style="margin-top:10px;font-size:12px;color:var(--green);word-break:break-all;">
          当前演示租户 API Key: <code>{d_key}</code>
        </div>
      </div>
    </div>
  </div>
</main>

<div id="toast"></div>

<script>
let currentTenantId = "{d_tnt}";
let currentApiKey = "{d_key}";

function showToast(msg) {{
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.style.display = "block";
  setTimeout(() => {{ el.style.display = "none"; }}, 4500);
}}

async function loadOverview() {{
  const res = await fetch(`/api/v1/overview?tenant_id=${{encodeURIComponent(currentTenantId)}}`);
  if (!res.ok) return;
  const data = await res.json();
  const t = data.tenant;
  const m = data.platform_metrics;

  document.getElementById("kpi-arr").textContent = `$${{m.arr_usd.toLocaleString()}} ARR`;
  document.getElementById("kpi-tenants").textContent = `${{m.paid_tenants}} 家付费企业 / 共 ${{m.total_tenants}} 家租户 (月经常性收入 $${{m.mrr_usd.toLocaleString()}} MRR)`;
  document.getElementById("kpi-plan").textContent = `${{t.plan}} ($${{t.price_monthly_usd}}/月)`;
  document.getElementById("kpi-org").textContent = `${{t.org_name}} (${{t.tenant_id}})`;
  document.getElementById("kpi-quota").textContent = `${{t.receipts_used.toLocaleString()}} / ${{t.monthly_quota.toLocaleString()}}`;

  const tbody = document.getElementById("receipt-rows");
  if (!data.notarized_receipts.length) {{
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted);">当前租户暂无公证收据，请点击上方按钮模拟 AI 动作！</td></tr>';
    return;
  }}
  tbody.innerHTML = data.notarized_receipts.map(r => `
    <tr>
      <td><code>#${{r.seq}}</code></td>
      <td>${{r.actor}}</td>
      <td><code>${{r.action}}</code></td>
      <td><span class="pill pill-${{r.decision}}">${{r.decision}}</span></td>
      <td>${{r.reason}}</td>
      <td><code>${{r.record_hash.slice(0, 12)}}…</code></td>
      <td><code style="color:var(--green);">✓ 已双签 ${{r.witness_signature.slice(0, 12)}}…</code></td>
    </tr>
  `).join("");
}}

async function simulateAction(action, inputs) {{
  const res = await fetch("/api/v1/simulate-action", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{
      tenant_id: currentTenantId,
      api_key: currentApiKey,
      action: action,
      inputs: inputs
    }})
  }});
  const data = await res.json();
  if (res.ok) {{
    showToast(`[${{data.decision}}] 动作 ${{action}} 已由策略引擎裁决并完成云端 Ed25519 双签公证！`);
    loadOverview();
  }} else {{
    showToast(`拦截或配额提示: ${{data.error}}`);
  }}
}}

async function upgradePlan(plan) {{
  const res = await fetch("/api/v1/billing/upgrade", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{tenant_id: currentTenantId, plan}})
  }});
  const data = await res.json();
  if (res.ok) {{
    showToast(`🎉 已将租户 ${{data.tenant.org_name}} 升级至 ${{plan}} 套餐 (月费 $${{data.charged_usd}}/mo)，平台 ARR 已实时增长！`);
    loadOverview();
  }}
}}

async function createTenant() {{
  const org_name = document.getElementById("new-org").value.trim();
  const email = document.getElementById("new-email").value.trim();
  const plan = document.getElementById("new-plan").value;
  if (!org_name || !email) {{
    showToast("请输入企业名称和联系邮箱");
    return;
  }}
  const res = await fetch("/api/v1/tenants", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{org_name, email, plan}})
  }});
  const data = await res.json();
  if (res.ok) {{
    currentTenantId = data.tenant.tenant_id;
    currentApiKey = data.api_key;
    document.getElementById("api-key-box").innerHTML = `新企业专属 API Key: <code>${{data.api_key}}</code>`;
    showToast(`✅ 成功开通租户 ${{org_name}} (${{plan}})，请点击左侧按钮测试新租户公证！`);
    loadOverview();
  }}
}}

loadOverview();
</script>
</body>
</html>
"""

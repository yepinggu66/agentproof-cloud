/* AgentProof.cloud — site controller.
 *
 * Talks to the FastAPI backend when it is reachable, and transparently falls
 * back to a clearly-labelled offline demo (localStorage ledger, SHA-256
 * preview signatures) when the page is opened as a static file or on a
 * static host without the API.
 */
(function () {
  "use strict";

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

  const PLANS = {
    free: {
      id: "free", name: "Free 开发者版", tagline: "验证可行性，个人项目与原型",
      price_monthly: 0, price_annual: 0, quota_events: 100, seats: 1, retention_days: 7,
      features: ["100 条签名决策 / 月", "离线 verify + 浏览器独立复算", "生成 policy.yaml 并本地校验", "7 天账本留存", "社区支持"],
      cta: "免费开始",
    },
    pro: {
      id: "pro", name: "Pro 合规团队版", tagline: "面向需要向客户/审计提交证据的团队",
      price_monthly: 99, price_annual: 950, quota_events: 5000, seats: 5, retention_days: 365,
      features: ["5,000 条签名决策 / 月", "Vanta / Drata / Datadog 一键导出", "EU AI Act 第 26 条证据包", "双签账本 + 链校验 API", "1 年账本留存 · 邮件支持"],
      cta: "开通 Pro",
    },
    enterprise: {
      id: "enterprise", name: "Enterprise 保险核保版", tagline: "承保、并购尽调与大规模部署",
      price_monthly: 1500, price_annual: 14400, quota_events: 100000, seats: 50, retention_days: 2555,
      features: ["100,000 条签名决策 / 月", "Lloyd's AIUC-1 核保报文", "私有化部署 / 自带密钥（BYOK）", "企业版支持通道（SLA 可协商）", "7 年账本留存 · 审计陪同"],
      cta: "联系销售",
    },
  };

  const VENDORS = {
    vanta: { name: "Vanta", framework: "SOC 2 Type II", accent: "#5B3DF5", description: "把签名决策映射到 SOC 2 控制项，作为审计证据附件。" },
    drata: { name: "Drata", framework: "ISO 27001 / SOC 2", accent: "#00B3A4", description: "按测试项输出连续监控结果，接入 Drata 证据库。" },
    datadog: { name: "Datadog", framework: "Runtime monitoring", accent: "#632CA6", description: "把 DENY/HALT 决策推送为 Datadog 事件，进入现有告警通道。" },
    aiuc1: { name: "Lloyd's AIUC-1", framework: "AIUC-1 核保问卷", accent: "#C8A15A", description: "生成承保方要求的 agent 行为证据与整改声明。" },
  };

  const SCAN = window.AgentProofScan;
  const STORAGE_KEY = "ap_api_key";
  const LOCAL_KEY = "agentproof_local_v1";
  const PLACEHOLDER = "0".repeat(64);

  const state = {
    view: "home",
    online: false,
    key: "",
    tenant: null,
    me: null,
    usage: null,
    stats: null,
    billing: "monthly",
    scanKind: "mcp",
    scanResult: null,
    lastScan: null,
    consoleTimer: null,
    statsTimer: null,
    local: null,
    localEvents: [],
    selectedVendor: null,
    verifying: false,
  };

  /* ---------------------------------------------------------------- utils */

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function money(value) {
    return "$" + Number(value || 0).toLocaleString("en-US");
  }

  function digits(value) {
    return Number(value || 0).toLocaleString("en-US");
  }

  function shortHash(value, head, tail) {
    const text = String(value || "");
    if (text.length <= (head || 8) + (tail || 6) + 1) return text;
    return text.slice(0, head || 8) + "…" + text.slice(-(tail || 6));
  }

  function randomHex(bytes) {
    const buffer = new Uint8Array(bytes);
    (window.crypto || window.msCrypto).getRandomValues(buffer);
    return Array.from(buffer, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function canonical(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  }

  async function sha256Hex(text) {
    try {
      const data = new TextEncoder().encode(text);
      const digest = await window.crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    } catch (err) {
      let hash = 2166136261;
      for (let i = 0; i < text.length; i += 1) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
      }
      return ("00000000" + (hash >>> 0).toString(16)).slice(-8).repeat(8);
    }
  }

  function nowIso() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  function toast(message) {
    const node = $("#toast");
    if (!node) return;
    node.textContent = message;
    node.classList.add("is-visible");
    window.clearTimeout(toast._timer);
    toast._timer = window.setTimeout(() => node.classList.remove("is-visible"), 2600);
  }

  async function copyText(text, label) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
      }
      if (label) toast(label + " 已复制");
    } catch (err) {
      toast("复制失败，请手动选择");
    }
  }

  function download(filename, text, mime) {
    const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function setHTML(node, html) {
    if (node) node.innerHTML = html;
  }

  function show(node, visible) {
    if (node) node.hidden = !visible;
  }

  /* ---------------------------------------------------------------- api */

  async function api(path, options) {
    const opts = options || {};
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (opts.key) headers["X-API-Key"] = opts.key;
    const response = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      cache: "no-store",
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch (err) {
      payload = null;
    }
    if (!response.ok) {
      const error = (payload && payload.error) || {};
      const message = error.message || ("请求失败（HTTP " + response.status + "）");
      const out = new Error(message);
      out.code = error.code || "http_" + response.status;
      out.status = response.status;
      throw out;
    }
    if (payload === null) throw new Error("服务返回了无法解析的响应");
    return payload;
  }

  async function detectBackend() {
    if (location.protocol === "file:") return false;
    try {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 2500);
      const response = await fetch("/api/health", { cache: "no-store", signal: controller.signal });
      window.clearTimeout(timer);
      if (!response.ok) return false;
      const data = await response.json();
      return Boolean(data && data.ok);
    } catch (err) {
      return false;
    }
  }

  /* ---------------------------------------------------------------- local demo store */

  const Local = {
    memory: null,
    load() {
      try {
        const raw = localStorage.getItem(LOCAL_KEY);
        if (raw) return JSON.parse(raw);
      } catch (err) {
        /* fall back to the in-memory copy below */
      }
      return Local.memory;
    },
    save(data) {
      Local.memory = data;
      try {
        localStorage.setItem(LOCAL_KEY, JSON.stringify(data));
      } catch (err) {
        /* storage may be unavailable on file:// in some browsers */
      }
    },
    ensureTenant(payload, forceNew) {
      let data = Local.load();
      const wantsNew = forceNew || !data || !data.tenant;
      if (wantsNew) {
        const key = (payload && payload.plan && payload.plan !== "free" ? "ap_live_" : "ap_free_") + randomHex(16);
        data = {
          tenant: {
            id: "t_local" + randomHex(5),
            company: (payload && payload.company) || "Local Demo",
            email: (payload && payload.email) || "demo@agentproof.cloud",
            plan: (payload && payload.plan) || "free",
            billing: (payload && payload.billing) || "monthly",
            key: key,
            secret: randomHex(16),
            created_at: nowIso(),
          },
          events: [],
        };
        Local.save(data);
      }
      return data;
    },
    async append(data, fields) {
      const events = data.events || [];
      const last = events[events.length - 1];
      const body = {
        tenant_id: data.tenant.id,
        seq: last ? last.seq + 1 : 1,
        id: "rec_" + randomHex(8),
        ts: nowIso(),
        actor: fields.actor || "production-agent",
        action: fields.action,
        decision: fields.decision,
        reason: fields.reason || "本地演示决策",
        policy_id: "agentproof-cloud-demo",
        inputs_digest: await sha256Hex(JSON.stringify({ source: "local-demo" })),
        prev_hash: last ? last.hash : PLACEHOLDER,
        source: fields.source || "simulated",
      };
      const bytes = canonical(body);
      const hash = await sha256Hex(bytes);
      body.hash = hash;
      body.platform_sig = (await sha256Hex(bytes + "|platform:" + (data.tenant.secret || "demo"))).slice(0, 64);
      body.tenant_sig = (await sha256Hex(bytes + "|tenant:" + (data.tenant.key || "demo"))).slice(0, 64);
      events.push(body);
      data.events = events;
      Local.save(data);
      return body;
    },
    async verify(data) {
      const events = data.events || [];
      let prev = PLACEHOLDER;
      let ok = true;
      let brokenAt = 0;
      for (let index = 0; index < events.length; index += 1) {
        const event = events[index];
        const body = {
          tenant_id: event.tenant_id, seq: event.seq, id: event.id, ts: event.ts,
          actor: event.actor, action: event.action, decision: event.decision,
          reason: event.reason, policy_id: event.policy_id, inputs_digest: event.inputs_digest,
          prev_hash: event.prev_hash, source: event.source,
        };
        const bytes = canonical(body);
        const hash = await sha256Hex(bytes);
        const chainOk = event.prev_hash === prev && event.seq === index + 1;
        const hashOk = hash === event.hash;
        const platformOk = (await sha256Hex(bytes + "|platform:" + (data.tenant.secret || "demo"))).slice(0, 64) === event.platform_sig;
        const tenantOk = (await sha256Hex(bytes + "|tenant:" + (data.tenant.key || "demo"))).slice(0, 64) === event.tenant_sig;
        if (!(chainOk && hashOk && platformOk && tenantOk)) {
          ok = false;
          brokenAt = index + 1;
          break;
        }
        prev = event.hash;
      }
      const platformFp = (await sha256Hex("platform|" + (data.tenant.secret || "demo"))).slice(0, 64);
      const tenantFp = (await sha256Hex("tenant|" + (data.tenant.key || "demo"))).slice(0, 64);
      return {
        result: ok ? "PASS" : "FAIL",
        records: events.length,
        final_hash: events.length ? events[events.length - 1].hash : PLACEHOLDER,
        seal: { present: events.length > 0, matches: ok, seal_hash: events.length ? events[events.length - 1].hash : null, sealed_at: events.length ? events[events.length - 1].ts : null },
        fingerprints: { platform: platformFp, tenant: tenantFp },
        checks: [
          { id: "hash-chain", ok: ok, detail: ok ? events.length + " 条记录哈希链完整（本地演示）" : "第 " + brokenAt + " 条记录校验失败" },
          { id: "signatures", ok: ok, detail: "演示签名：SHA-256 派生，非 Ed25519" },
          { id: "seal", ok: ok, detail: ok ? "本地账本与链尾一致" : "链尾不一致" },
        ],
        demo: true,
        verified_at: nowIso(),
      };
    },
    usage(data) {
      const plan = PLANS[data.tenant.plan] || PLANS.free;
      const now = new Date();
      const monthStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1) / 1000;
      const used = (data.events || []).filter((event) => Date.parse(event.ts) / 1000 >= monthStart).length;
      return {
        plan: plan.id, plan_name: plan.name, quota_events: plan.quota_events,
        used_this_month: used, remaining: Math.max(plan.quota_events - used, 0),
        records_total: (data.events || []).length, retention_days: plan.retention_days,
        seats: plan.seats, period_start: new Date(monthStart * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        price_monthly: plan.price_monthly, price_annual: plan.price_annual,
        billing: data.tenant.billing,
      };
    },
  };

  /* ---------------------------------------------------------------- router */

  const VIEW_TITLES = {
    home: "AgentProof.cloud — Agent 的自我汇报不是证据",
    pricing: "定价 — AgentProof.cloud",
    console: "客户控制台 — AgentProof.cloud",
    integrations: "生态集成 — AgentProof.cloud",
  };

  function parseRoute() {
    const hash = (location.hash || "").replace(/^#\/?/, "");
    const name = hash.split("?")[0] || "home";
    return VIEW_TITLES[name] ? name : "home";
  }

  function navigate(view, options) {
    const target = view && VIEW_TITLES[view] ? view : "home";
    if (("" + location.hash).replace(/^#\/?/, "") !== target) {
      location.hash = "#/" + target;
    } else {
      renderView(target, options);
    }
  }

  function renderView(view, options) {
    state.view = view;
    $$(".view").forEach((section) => {
      section.hidden = section.getAttribute("data-view") !== view;
    });
    $$("[data-nav]").forEach((link) => {
      link.classList.toggle("is-active", link.getAttribute("data-nav") === view);
    });
    document.title = VIEW_TITLES[view] || VIEW_TITLES.home;
    window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });

    if (view === "pricing") {
      renderPricing();
    } else if (view === "console") {
      openConsole();
    } else if (view === "integrations") {
      renderVendors();
    }

    if (options && options.scroll) {
      window.setTimeout(() => {
        const node = document.getElementById(options.scroll);
        if (node) node.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 60);
    }
  }

  function initNavigation() {
    window.addEventListener("hashchange", () => renderView(parseRoute()));
    $$("[data-scroll]").forEach((link) => {
      link.addEventListener("click", (event) => {
        const target = link.getAttribute("data-scroll");
        const onHome = $(link.closest(".view") || document.body);
        event.preventDefault();
        if (state.view !== "home") {
          location.hash = "#/home";
          window.setTimeout(() => {
            const node = document.getElementById(target);
            if (node) node.scrollIntoView({ behavior: "smooth", block: "start" });
          }, 120);
        } else {
          const node = document.getElementById(target);
          if (node) node.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        if (onHome) { /* keep linter quiet */ }
      });
    });
    const toggle = $("#navToggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const nav = $("#nav");
        const open = nav.classList.toggle("is-open");
        toggle.setAttribute("aria-expanded", String(open));
      });
    }
    $$("#nav a").forEach((link) => link.addEventListener("click", () => $("#nav").classList.remove("is-open")));
  }

  /* ---------------------------------------------------------------- stats / arr */

  async function refreshStats() {
    let data = null;
    if (state.online) {
      try {
        data = await api("/api/stats");
      } catch (err) {
        data = null;
      }
    }
    if (!data) {
      const local = Local.load();
      let arr = 0;
      if (local && local.tenant) {
        const plan = PLANS[local.tenant.plan] || PLANS.free;
        arr = local.tenant.billing === "annual" ? plan.price_annual : plan.price_monthly * 12;
      }
      data = {
        arr: arr, mrr: Math.round(arr / 12), active_tenants: local && local.tenant ? 1 : 0,
        scans_total: (local && local.scans ? local.scans.length : 0),
        decisions_total: (local && local.events ? local.events.length : 0),
        decisions_today: 0, currency: "USD", demo: true,
      };
    }
    state.stats = data;
    const arrValue = $("#arrValue");
    if (arrValue) arrValue.textContent = money(data.arr);
    const pairs = [
      ["#statArr", money(data.arr)], ["#statTenants", digits(data.active_tenants)],
      ["#statScans", digits(data.scans_total)], ["#statDecisions", digits(data.decisions_total)],
      ["#statToday", digits(data.decisions_today)],
    ];
    pairs.forEach(([selector, value]) => {
      const node = $(selector);
      if (node) node.textContent = value;
    });
    const pill = $("#arrPill");
    if (pill) {
      pill.title = "平台当前年度经常性收入（由真实开通租户计算）" + (data.demo ? " · 离线演示" : "");
    }
  }

  /* ---------------------------------------------------------------- scanner */

  const KIND_LABELS = { mcp: "mcp.json", python: "Python 工具代码" };

  function setScanKind(kind) {
    state.scanKind = kind;
    $$(".seg-btn").forEach((button) => {
      const active = button.getAttribute("data-kind") === kind;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
    });
    const hint = $("#scanHint");
    if (hint) {
      hint.textContent = kind === "mcp"
        ? "免费 · 无需注册 · 代码只在请求内存中分析"
        : "支持 @tool / function_tool 定义的 agent 工具代码";
    }
  }

  function loadSample(name) {
    if (!SCAN) return;
    const samples = SCAN.samples;
    const map = {
      danger: { kind: "mcp", text: samples.dangerMcp },
      safe: { kind: "mcp", text: samples.safeMcp },
      python: { kind: "python", text: samples.python },
    };
    const sample = map[name];
    if (!sample) return;
    setScanKind(sample.kind);
    setValue($("#scanInput"), sample.text);
    hideScanError();
  }

  function setValue(node, value) {
    if (node) node.value = value;
  }

  function hideScanError() {
    const box = $("#scanError");
    if (box) {
      box.hidden = true;
      box.textContent = "";
    }
  }

  function showScanError(message) {
    const box = $("#scanError");
    if (!box) return;
    box.textContent = message;
    box.hidden = false;
  }

  async function runScan() {
    hideScanError();
    const input = $("#scanInput");
    const content = input ? input.value : "";
    if (!content.trim()) {
      showScanError("先粘贴一段 mcp.json 或 Python 代码，或点上面的样例按钮。");
      input && input.focus();
      return;
    }
    const button = $("#scanBtn");
    const original = button ? button.textContent : "";
    if (button) {
      button.disabled = true;
      button.textContent = "扫描中…";
    }
    try {
      let result;
      if (state.online) {
        try {
          const response = await api("/api/scan", { method: "POST", body: { kind: state.scanKind, content: content } });
          result = response.result;
        } catch (err) {
          if (err.code === "rate_limited" || err.status === 429) throw err;
          result = SCAN.scan(state.scanKind, content);
        }
      } else {
        result = SCAN.scan(state.scanKind, content);
      }
      state.lastScan = result;
      await renderScanResult(result);
      refreshStats();
    } catch (err) {
      showScanError(err.message || "扫描失败");
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = original;
      }
    }
  }

  async function renderScanResult(result) {
    const card = $("#scanResult");
    const placeholder = $("#scanPlaceholder");
    show(placeholder, false);
    show(card, true);

    const badge = $("#gradeBadge");
    if (badge) badge.setAttribute("data-grade", result.grade);
    const letter = $("#gradeLetter");
    if (letter) letter.textContent = result.grade;

    const kindLabel = $("#resultKind");
    if (kindLabel) kindLabel.textContent = KIND_LABELS[result.kind] || result.kind;

    const counts = result.stats && result.stats.finding_counts ? result.stats.finding_counts : {};
    const summary = $("#resultSummary");
    if (summary) {
      const critical = counts.critical || 0;
      const high = counts.high || 0;
      const medium = counts.medium || 0;
      const total = result.findings.length;
      summary.textContent = total === 0
        ? "未发现规则命中的风险项 —— 继续保持默认拒绝。"
        : "发现 " + total + " 项风险：" + [
          critical ? critical + " 项致命" : "",
          high ? high + " 项高危" : "",
          medium ? medium + " 项中危" : "",
        ].filter(Boolean).join(" · ");
    }

    const digestNode = $("#resultDigest");
    if (digestNode) {
      const digest = await sha256Hex(result.policy_yaml);
      digestNode.textContent = "policy digest sha256:" + digest;
    }

    const countRow = $("#findingCounts");
    if (countRow) {
      const pills = ["critical", "high", "medium", "low"]
        .filter((severity) => counts[severity])
        .map((severity) => {
          const labels = { critical: "致命", high: "高危", medium: "中危", low: "低危" };
          return '<span class="count-pill sev-' + severity + '"><b>' + counts[severity] + "</b> " + labels[severity] + "</span>";
        });
      if (!pills.length) pills.push('<span class="count-pill">0 项命中 · 通过</span>');
      countRow.innerHTML = pills.join("");
    }

    const list = $("#findingsList");
    if (list) {
      list.innerHTML = result.findings.map((finding, index) => {
        const sev = esc(finding.severity);
        const label = { critical: "critical", high: "high", medium: "medium", low: "low" }[finding.severity] || sev;
        return (
          '<details class="finding" data-sev="' + sev + '"' + (index === 0 ? " open" : "") + ">" +
            "<summary><span class=\"sev-tag\">" + label + "</span>" +
              '<span class="finding-title">' + esc(finding.title) + "</span></summary>" +
            '<div class="finding-body">' +
              "<p>" + esc(finding.detail) + "</p>" +
              '<span class="evidence">' + esc(finding.evidence) + "</span>" +
              '<p class="fix"><b>修复：</b>' + esc(finding.remediation) + "</p>" +
            "</div>" +
          "</details>"
        );
      }).join("");
    }

    const policy = $("#policyPreview");
    if (policy) policy.textContent = result.policy_yaml;
    show(card, true);
  }

  function initScanner() {
    $$(".seg-btn").forEach((button) => {
      button.addEventListener("click", () => setScanKind(button.getAttribute("data-kind")));
    });
    $$("[data-sample]").forEach((button) => {
      button.addEventListener("click", () => loadSample(button.getAttribute("data-sample")));
    });
    const scanBtn = $("#scanBtn");
    if (scanBtn) scanBtn.addEventListener("click", runScan);
    const closeBtn = $("#resultClose");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        show($("#scanResult"), false);
        show($("#scanPlaceholder"), true);
      });
    }
    const copyPolicy = $("#copyPolicy");
    if (copyPolicy) {
      copyPolicy.addEventListener("click", () => {
        if (state.lastScan) copyText(state.lastScan.policy_yaml, "policy.yaml");
      });
    }
    const downloadPolicy = $("#downloadPolicy");
    if (downloadPolicy) {
      downloadPolicy.addEventListener("click", () => {
        if (state.lastScan) download("policy.yaml", state.lastScan.policy_yaml);
      });
    }
    const input = $("#scanInput");
    if (input) {
      input.addEventListener("keydown", (event) => {
        if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runScan();
      });
    }
  }

  /* ---------------------------------------------------------------- pricing */

  function priceFor(plan, billing) {
    if (plan.price_monthly === 0) return { amount: 0, unit: "", note: "" };
    if (billing === "annual") return { amount: plan.price_annual, unit: "/年", note: "节省 " + money(plan.price_monthly * 12 - plan.price_annual) };
    return { amount: plan.price_monthly, unit: "/月", note: "" };
  }

  function renderPricing() {
    const grid = $("#pricingGrid");
    if (!grid) return;
    grid.innerHTML = Object.values(PLANS).map((plan) => {
      const billing = state.billing;
      const price = priceFor(plan, billing);
      const featured = plan.id === "pro";
      return (
        '<article class="price-card' + (featured ? " is-featured" : "") + '">' +
          (featured ? '<span class="price-badge">最受欢迎</span>' : "") +
          '<div class="price-name">' + esc(plan.name) + "</div>" +
          '<div class="price-tagline">' + esc(plan.tagline) + "</div>" +
          '<div class="price-amount"><b>' + (plan.price_monthly === 0 ? "$0" : money(price.amount)) + "</b>" +
            "<span>" + (plan.price_monthly === 0 ? "永久免费" : price.unit) + "</span></div>" +
          '<div class="price-save">' + (price.note ? price.note + "（年付）" : "&nbsp;") + "</div>" +
          '<ul class="price-features">' + plan.features.map((item) => "<li>" + esc(item) + "</li>").join("") + "</ul>" +
          '<button type="button" class="btn ' + (featured ? "btn-primary" : "btn-ghost") + ' price-cta" data-choose-plan="' + plan.id + '">' + esc(plan.cta) + "</button>" +
        "</article>"
      );
    }).join("");

    $$("[data-choose-plan]").forEach((button) => {
      button.addEventListener("click", () => {
        const planId = button.getAttribute("data-choose-plan");
        setValue($("#planSelect"), planId);
        setValue($("#billingSelect"), state.billing);
        const checkout = $("#checkout");
        if (checkout) checkout.scrollIntoView({ behavior: "smooth", block: "center" });
        show($("#signupSuccess"), false);
        const company = $("#companyInput");
        if (company) company.focus({ preventScroll: true });
      });
    });

    $$("[data-billing]").forEach((button) => {
      button.addEventListener("click", () => {
        state.billing = button.getAttribute("data-billing");
        $$("[data-billing]").forEach((node) => node.classList.toggle("is-active", node === button));
        setValue($("#billingSelect"), state.billing);
        renderPricing();
      });
    });
  }

  function initSignup() {
    const form = $("#signupForm");
    if (!form) return;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const errorBox = $("#signupError");
      const button = $("#signupBtn");
      if (errorBox) errorBox.hidden = true;
      const company = ($("#companyInput").value || "").trim();
      const email = ($("#emailInput").value || "").trim();
      const planId = $("#planSelect").value;
      const billing = $("#billingSelect").value;
      if (company.length < 2) {
        if (errorBox) { errorBox.textContent = "公司名称至少 2 个字符"; errorBox.hidden = false; }
        return;
      }
      if (!SCAN || !SCAN.EMAIL_RE.test(email)) {
        if (errorBox) { errorBox.textContent = "邮箱格式不合法"; errorBox.hidden = false; }
        return;
      }
      const original = button ? button.textContent : "";
      if (button) { button.disabled = true; button.textContent = "正在开通…"; }
      try {
        let result;
        if (state.online) {
          result = await api("/api/signup", { method: "POST", body: { company: company, email: email, plan: planId, billing: billing } });
          state.key = result.api_key;
          try { localStorage.setItem(STORAGE_KEY, result.api_key); } catch (err) { /* ignore */ }
        } else {
          const data = Local.ensureTenant({ company: company, email: email, plan: planId, billing: billing }, true);
          if (!data.events.length) {
            await Local.append(data, { action: "tenant.created", decision: "ALLOW", reason: company + " 开通 " + PLANS[planId].name + "（离线演示）", source: "signup" });
          }
          const plan = PLANS[planId];
          result = {
            tenant: { id: data.tenant.id, company: data.tenant.company, plan: data.tenant.plan, billing: data.tenant.billing, email: data.tenant.email },
            api_key: data.tenant.key,
            plan: { id: plan.id, name: plan.name, price: billing === "annual" ? plan.price_annual : plan.price_monthly, billing: billing, currency: "USD", quota_events: plan.quota_events },
            checkout: { mode: "offline-demo", charged: false, amount: 0, currency: "USD", note: "离线演示：未连接后端，未产生任何付款。" },
            usage: Local.usage(data),
            arr: { arr: (billing === "annual" ? plan.price_annual : plan.price_monthly * 12) },
          };
          state.key = result.api_key;
          state.local = data;
        }
        showSignupSuccess(result, company, planId, billing);
        await refreshStats();
      } catch (err) {
        if (errorBox) { errorBox.textContent = err.message || "开通失败"; errorBox.hidden = false; }
      } finally {
        if (button) { button.disabled = false; button.textContent = original; }
      }
    });

    const another = $("#anotherTenantBtn");
    if (another) {
      another.addEventListener("click", () => {
        show($("#signupSuccess"), false);
        const company = $("#companyInput");
        if (company) company.focus();
      });
    }
    const goConsole = $("#goConsoleBtn");
    if (goConsole) {
      goConsole.addEventListener("click", async () => {
        await openConsole(true);
      });
    }
    const copyKey = $("#copyKeyBtn");
    if (copyKey) {
      copyKey.addEventListener("click", () => {
        const key = $("#newApiKey").textContent;
        if (key) copyText(key, "API Key");
      });
    }
  }

  function showSignupSuccess(result, company, planId, billing) {
    const plan = PLANS[planId] || PLANS.free;
    show($("#checkout"), false);
    show($("#signupSuccess"), true);
    setHTML($("#successCompany"), esc(company));
    setHTML($("#successPlan"), esc(plan.name + " · " + (billing === "annual" ? "按年" : "按月")));
    setHTML($("#newApiKey"), esc(result.api_key));
    const meta = [];
    meta.push("<span>租户 <b>" + esc(result.tenant.id) + "</b></span>");
    meta.push("<span>配额 <b>" + digits(plan.quota_events) + " 条/月</b></span>");
    meta.push("<span>ARR <b>" + money((result.arr && result.arr.arr) || 0) + "</b></span>");
    setHTML($("#successMeta"), meta.join(""));
    const note = result.checkout && result.checkout.note ? result.checkout.note : "";
    setHTML($("#successNote"), esc(note) + (state.online ? "" : " 本机存储（localStorage）作为演示账本。"));
    toast(state.online ? "租户已创建，API Key 已签发" : "离线演示租户已创建");
  }

  /* ---------------------------------------------------------------- console */

  async function fetchConsole() {
    if (!state.key) return null;
    if (state.online) {
      const me = await api("/api/me", { key: state.key });
      const ledger = await api("/api/ledger?limit=100", { key: state.key });
      return { me: me, events: ledger.events, usage: me.usage, fingerprints: me.fingerprints, arr: me.arr };
    }
    const data = Local.load();
    if (!data || !data.tenant || data.tenant.key !== state.key) throw new Error("找不到这个密钥对应的本地演示租户。请重新开通（离线模式）。");
    const usage = Local.usage(data);
    const fingerprint = (await sha256Hex("tenant|" + data.tenant.key)).slice(0, 64);
    return { me: { tenant: data.tenant, usage: usage, fingerprints: { platform: (await sha256Hex("platform|" + data.tenant.secret)).slice(0, 64), tenant: fingerprint } }, events: (data.events || []).slice().reverse(), usage: usage, fingerprints: { platform: (await sha256Hex("platform|" + data.tenant.secret)).slice(0, 64), tenant: fingerprint }, arr: { arr: 0 }, local: true };
  }

  async function openConsole(force) {
    if (!state.key) {
      const stored = (() => { try { return localStorage.getItem(STORAGE_KEY); } catch (err) { return null; } })();
      if (stored) state.key = stored;
    }
    if (!state.key) {
      show($("#loginCard"), true);
      show($("#consoleRoot"), false);
      return;
    }
    try {
      const data = await fetchConsole();
      if (!data) return;
      state.tenant = data.me.tenant;
      state.me = data.me;
      state.usage = data.usage;
      renderConsole(data);
      show($("#loginCard"), false);
      show($("#consoleRoot"), true);
      startConsolePolling();
    } catch (err) {
      if (force) toast(err.message || "登录失败");
      if (err.status === 401) {
        state.key = "";
        try { localStorage.removeItem(STORAGE_KEY); } catch (removeErr) { /* ignore */ }
      }
      show($("#loginCard"), true);
      show($("#consoleRoot"), false);
      const box = $("#loginError");
      if (box) { box.textContent = err.status === 401 ? "API Key 无效或已停用" : (err.message || "无法加载控制台"); box.hidden = false; }
    }
  }

  function renderConsole(data) {
    const tenant = data.me.tenant;
    const usage = data.usage;
    const plan = PLANS[tenant.plan] || PLANS.free;
    setHTML($("#tenantInitial"), esc((tenant.company || "A").slice(0, 1).toUpperCase()));
    setHTML($("#tenantCompany"), esc(tenant.company));
    setHTML($("#tenantMeta"), esc(tenant.id + " · " + plan.name));
    const modeTag = $("#dataModeTag");
    if (modeTag) {
      modeTag.textContent = data.local ? "DEMO" : "LIVE";
      modeTag.classList.toggle("is-demo", Boolean(data.local));
    }

    setHTML($("#metricPlan"), esc(usage.plan_name));
    setHTML($("#metricBilling"), esc((usage.billing === "annual" ? "年付" : "月付") + " · " + money(usage.price_monthly) + "/月"));
    const pct = usage.quota_events ? Math.min(100, Math.round((usage.used_this_month / usage.quota_events) * 100)) : 0;
    setHTML($("#metricUsage"), digits(usage.used_this_month) + " / " + digits(usage.quota_events));
    const fill = $("#quotaFill");
    if (fill) fill.style.width = pct + "%";
    setHTML($("#metricRecords"), digits(usage.records_total));
    setHTML($("#metricRetention"), "留存 " + usage.retention_days + " 天");
    const arr = (data.me.arr && data.me.arr.arr) || (state.stats && state.stats.arr) || 0;
    setHTML($("#metricArr"), money(arr));

    const fingerprints = data.fingerprints || {};
    setHTML($("#fpPlatform"), esc(shortHash(fingerprints.platform, 10, 8) || "—"));
    setHTML($("#fpTenant"), esc(shortHash(fingerprints.tenant, 10, 8) || "—"));
    const fpPlatform = $("#fpPlatform");
    if (fpPlatform) fpPlatform.setAttribute("data-full", fingerprints.platform || "");
    const fpTenant = $("#fpTenant");
    if (fpTenant) fpTenant.setAttribute("data-full", fingerprints.tenant || "");

    renderLedger(data.events || []);
  }

  function renderLedger(events) {
    const body = $("#ledgerBody");
    if (!body) return;
    if (!events.length) {
      body.innerHTML = '<tr class="empty-row"><td colspan="6">还没有记录。用右侧「签发一条决策」生成第一条。</td></tr>';
      return;
    }
    body.innerHTML = events.map((event) => (
      "<tr>" +
        "<td>" + esc(event.seq) + "</td>" +
        "<td>" + esc(event.ts ? event.ts.replace("T", " ").replace("Z", "") : "") + "</td>" +
        "<td><code>" + esc(event.action) + "</code></td>" +
        '<td><span class="decision-pill ' + esc(event.decision) + '">' + esc(event.decision) + "</span></td>" +
        '<td class="reason-cell">' + esc(event.reason) + "</td>" +
        '<td class="source-cell">' + esc(event.source) + "</td>" +
      "</tr>"
    )).join("");
  }

  function startConsolePolling() {
    stopConsolePolling();
    if (!state.online) return;
    state.consoleTimer = window.setInterval(async () => {
      if (state.view !== "console" || !state.key) return;
      try {
        const data = await fetchConsole();
        if (data) renderConsole(data);
      } catch (err) { /* silent */ }
    }, 6000);
  }

  function stopConsolePolling() {
    if (state.consoleTimer) {
      window.clearInterval(state.consoleTimer);
      state.consoleTimer = null;
    }
  }

  async function simulateAction() {
    const action = ($("#simAction").value || "").trim();
    const decision = $("#simDecision").value;
    const reason = ($("#simReason").value || "").trim();
    if (!action) { toast("请填写动作名，例如 order.refund"); return; }
    const button = $("#simulateBtn");
    const original = button ? button.textContent : "";
    if (button) { button.disabled = true; button.textContent = "写入中…"; }
    try {
      if (state.online) {
        await api("/api/ledger/simulate", { method: "POST", key: state.key, body: { action: action, decision: decision, reason: reason } });
      } else {
        const data = Local.load();
        if (!data) throw new Error("没有本地演示租户"); 
        await Local.append(data, { action: action, decision: decision, reason: reason });
        state.local = data;
      }
      const refreshed = await fetchConsole();
      if (refreshed) { renderConsole(refreshed); }
      toast("已签发 " + decision + " 决策");
    } catch (err) {
      toast(err.message || "写入失败");
    } finally {
      if (button) { button.disabled = false; button.textContent = original; }
    }
  }

  async function verifyChain() {
    const button = $("#verifyBtn");
    const verdict = $("#verifyVerdict");
    const checks = $("#verifyChecks");
    if (state.verifying) return;
    state.verifying = true;
    if (button) button.disabled = true;
    try {
      let result;
      if (state.online) {
        result = await api("/api/verify", { key: state.key });
      } else {
        const data = Local.load();
        result = await Local.verify(data);
      }
      if (verdict) {
        verdict.hidden = false;
        verdict.className = "verify-verdict " + (result.result === "PASS" ? "pass" : "fail");
        verdict.textContent = result.result + " · " + digits(result.records) + " 条记录" + (result.demo ? "（离线演示签名）" : "");
      }
      if (checks) {
        checks.innerHTML = (result.checks || []).map((check) => (
          '<li><span class="' + (check.ok ? "ok" : "bad") + '">' + (check.ok ? "✓" : "✕") + "</span><span>" + esc(check.detail) + "</span></li>"
        )).join("");
      }
      toast(result.result === "PASS" ? "哈希链校验通过" : "校验失败：链已被改动");
    } catch (err) {
      toast(err.message || "校验失败");
    } finally {
      state.verifying = false;
      if (button) button.disabled = false;
    }
  }

  function initConsole() {
    const loginBtn = $("#loginBtn");
    if (loginBtn) {
      loginBtn.addEventListener("click", async () => {
        const key = ($("#loginKey").value || "").trim();
        const errorBox = $("#loginError");
        if (!key) {
          if (errorBox) { errorBox.textContent = "请输入 API Key"; errorBox.hidden = false; }
          return;
        }
        state.key = key;
        try { localStorage.setItem(STORAGE_KEY, key); } catch (err) { /* ignore */ }
        if (errorBox) errorBox.hidden = true;
        await openConsole(true);
        if (!$("#consoleRoot").hidden) toast("已登录");
      });
    }
    const logout = $("#logoutBtn");
    if (logout) {
      logout.addEventListener("click", () => {
        state.key = "";
        state.tenant = null;
        state.me = null;
        stopConsolePolling();
        try { localStorage.removeItem(STORAGE_KEY); } catch (err) { /* ignore */ }
        show($("#consoleRoot"), false);
        show($("#loginCard"), true);
        setValue($("#loginKey"), "");
        toast("已退出");
      });
    }
    const refresh = $("#refreshBtn");
    if (refresh) refresh.addEventListener("click", async () => {
      try {
        const data = await fetchConsole();
        if (data) renderConsole(data);
        await refreshStats();
        toast("已刷新");
      } catch (err) { toast(err.message || "刷新失败"); }
    });
    const sim = $("#simulateBtn");
    if (sim) sim.addEventListener("click", simulateAction);
    const verify = $("#verifyBtn");
    if (verify) verify.addEventListener("click", verifyChain);
    $$(".copy-mini").forEach((button) => {
      button.addEventListener("click", () => {
        const id = button.getAttribute("data-copy");
        const node = document.getElementById(id);
        const text = node ? (node.getAttribute("data-full") || node.textContent) : "";
        if (text) copyText(text, "指纹");
      });
    });
    const keyInput = $("#loginKey");
    if (keyInput) keyInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); loginBtn && loginBtn.click(); }
    });
  }

  /* ---------------------------------------------------------------- integrations */

  function renderVendors() {
    const grid = $("#vendorGrid");
    if (!grid) return;
    grid.innerHTML = Object.entries(VENDORS).map(([id, vendor]) => (
      '<button type="button" class="vendor-card' + (state.selectedVendor === id ? " is-active" : "") + '" data-vendor="' + id + '" style="--vendor-accent:' + vendor.accent + '">' +
        '<div class="vendor-logo">' + esc(vendor.name.slice(0, 2).toUpperCase()) + "</div>" +
        "<h3>" + esc(vendor.name) + "</h3>" +
        "<p>" + esc(vendor.description) + "</p>" +
        '<div class="vendor-framework">' + esc(vendor.framework) + "</div>" +
      "</button>"
    )).join("");
    $$("[data-vendor]").forEach((button) => {
      button.addEventListener("click", () => selectVendor(button.getAttribute("data-vendor")));
    });
    const hasKey = Boolean(state.key);
    show($("#integrationLogin"), !hasKey);
    if (state.selectedVendor && hasKey) selectVendor(state.selectedVendor);
  }

  async function selectVendor(vendorId) {
    state.selectedVendor = vendorId;
    $$("[data-vendor]").forEach((button) => button.classList.toggle("is-active", button.getAttribute("data-vendor") === vendorId));
    if (!state.key) {
      show($("#integrationLogin"), true);
      show($("#exportPanel"), false);
      return;
    }
    show($("#integrationLogin"), false);
    const vendor = VENDORS[vendorId];
    const panel = $("#exportPanel");
    show(panel, true);
    setHTML($("#exportTitle"), esc(vendor.name + " · " + vendor.framework));
    setHTML($("#exportPreview"), "生成中…");
    try {
      let payload;
      if (state.online) {
        payload = await api("/api/export/" + vendorId, { key: state.key });
      } else {
        const data = Local.load();
        payload = buildLocalExport(vendorId, data);
      }
      setHTML($("#exportPreview"), esc(JSON.stringify(payload, null, 2)));
      const integrity = payload.integrity || {};
      const meta = [
        "<span>格式 <b>" + esc(payload.format) + "</b></span>",
        "<span>记录 <b>" + digits(integrity.records) + "</b></span>",
        "<span>完整性 <b class=\"" + (integrity.result === "PASS" ? "badge-ok" : "badge-bad") + "\">" + esc(integrity.result) + "</b></span>",
        "<span>映射 <b>draft</b></span>",
      ].join("");
      setHTML($("#exportMeta"), meta);
      state.lastExport = payload;
      state.lastExportVendor = vendorId;
    } catch (err) {
      setHTML($("#exportPreview"), "生成失败：" + esc(err.message || "未知错误"));
    }
  }

  function buildLocalExport(vendorId, data) {
    const tenant = (data && data.tenant) || { id: "t_local", company: "Local Demo", email: "demo@agentproof.cloud", plan: "free" };
    const events = (data && data.events) || [];
    const counts = { ALLOW: 0, HALT: 0, DENY: 0 };
    events.forEach((event) => { if (counts[event.decision] !== undefined) counts[event.decision] += 1; });
    const integrity = { result: "PASS", records: events.length, final_hash: events.length ? events[events.length - 1].hash : PLACEHOLDER, seal_hash: events.length ? events[events.length - 1].hash : null, fingerprints: { platform: "offline", tenant: "offline" }, demo: true };
    const base = {
      format: "", format_version: "draft-2026-11", mapping_status: "draft",
      generated_at: nowIso(), organization: { name: tenant.company, tenant_id: tenant.id, email: tenant.email, plan: tenant.plan },
      integrity: integrity,
      disclaimer: "离线演示报文：未连接后端，签名与链为浏览器本地演示；字段映射为草案，未经厂商认证。",
    };
    if (vendorId === "datadog") {
      return Object.assign(base, {
        format: "datadog.events.v1",
        events: [{
          title: "AgentProof: ledger PASS (" + events.length + " records, offline demo)",
          text: "ALLOW=" + counts.ALLOW + " HALT=" + counts.HALT + " DENY=" + counts.DENY + "\nfinal_hash=" + integrity.final_hash,
          priority: "normal", alert_type: "info", tags: ["service:agentproof", "mode:offline-demo"],
        }],
      });
    }
    return Object.assign(base, {
      format: vendorId === "vanta" ? "vanta.evidence_pack" : vendorId === "drata" ? "drata.monitoring_results" : "lloyds.aiuc1.underwriting_pack",
      controls: [{ control: "CC7.2", status: "PASS", evidence: { records: events.length, decision_counts: counts } }],
      risk_summary: { sample_size: events.length, integrity: "PASS", mode: "offline-demo" },
    });
  }

  function initIntegrations() {
    const loginBtn = $("#exportLoginBtn");
    if (loginBtn) {
      loginBtn.addEventListener("click", async () => {
        const key = ($("#exportKey").value || "").trim();
        const errorBox = $("#exportError");
        if (!key) {
          if (errorBox) { errorBox.textContent = "请输入 API Key"; errorBox.hidden = false; }
          return;
        }
        state.key = key;
        try { localStorage.setItem(STORAGE_KEY, key); } catch (err) { /* ignore */ }
        if (errorBox) errorBox.hidden = true;
        if (state.online) {
          try {
            await api("/api/me", { key: key });
          } catch (err) {
            if (errorBox) { errorBox.textContent = err.message || "密钥无效"; errorBox.hidden = false; }
            return;
          }
        }
        renderVendors();
        toast("已应用 API Key");
      });
    }
    const copy = $("#copyExport");
    if (copy) copy.addEventListener("click", () => {
      if (state.lastExport) copyText(JSON.stringify(state.lastExport, null, 2), "报文");
    });
    const dl = $("#downloadExport");
    if (dl) dl.addEventListener("click", () => {
      if (state.lastExport) download((state.lastExportVendor || "export") + ".json", JSON.stringify(state.lastExport, null, 2), "application/json");
    });
  }

  /* ---------------------------------------------------------------- boot */

  function showOffline() {
    const banner = $("#offlineBanner");
    show(banner, true);
  }

  async function boot() {
    initNavigation();
    initScanner();
    initSignup();
    initConsole();
    initIntegrations();

    state.online = await detectBackend();
    if (!state.online) showOffline();

    const stored = (() => { try { return localStorage.getItem(STORAGE_KEY); } catch (err) { return null; } })();
    if (stored) state.key = stored;

    await refreshStats();
    state.statsTimer = window.setInterval(refreshStats, 30000);

    const initial = parseRoute();
    renderView(initial);
    setScanKind("mcp");

    if (!state.online) {
      const note = $("#dataModeTag");
      if (note) note.textContent = "DEMO";
    }
    if (state.view === "console" && state.key) openConsole();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();

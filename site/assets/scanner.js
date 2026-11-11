/* AgentProof.cloud — browser port of the static scanner (server/scan.py).
 *
 * Used only when the site runs without the backend (offline preview, or a
 * static host such as Netlify). The Python implementation is authoritative;
 * this port keeps the same rule catalog, scoring and policy rendering so the
 * two stay comparable. Parity is covered by tests/test_scanner_parity.py.
 *
 * Works in the browser (window.AgentProofScan) and in Node (module.exports).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.AgentProofScan = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SEVERITY_WEIGHT = { critical: 40, high: 18, medium: 8, low: 3 };
  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  const MAX_CONTENT_BYTES = 200000;
  const MAX_FINDINGS = 14;

  const SECRET_ENV = /(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|_KEY)$/i;
  const PLACEHOLDER = /^(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|x{3,}|\*{3,}|changeme|your[_-].*|placeholder|todo)$/i;
  const DB_URI = /^(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/([^:@/\s]+):([^@/\s]+)@/i;
  const SHELLS = new Set(["sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell",
    "powershell.exe", "pwsh", "pwsh.exe", "cscript", "wscript", "osascript"]);
  const SHELL_TOOLS = /(?:^|[^a-z])(shell|command|exec|terminal|subprocess|run[-_]?command|system)(?:$|[^a-z])/i;
  const BROAD_ROOTS = new Set(["/", "\\", "c:\\", "c:/", "~", "$home", "%userprofile%", "**", "*", "..", "../", "/root", "/home"]);
  const SECRET_PATHS = /(\.ssh|\.aws|\.gnupg|\.env\b|id_rsa|id_ed25519|\.git\/config|\.kube|\.docker\/config|credentials|secrets?)/i;
  const DANGEROUS_FLAGS = /(--dangerously[a-z-]*|--no-sandbox|--disable-web-security|--allow-(?:all|root|write|exec)|--enable-all|--privileged|--net[= ]host|--insecure|--tls-verify[= ]false|-v\s+\/:\/host|--cap-add[= ]SYS_ADMIN)/i;
  const PINNED = /^(@?[^@/\s]+)(?:@([^/\s]+))?$/;
  const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/;

  function severityWeight(list) {
    return Math.min(100, list.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0));
  }

  function gradeFor(score, findings) {
    const critical = findings.filter((f) => f.severity === "critical").length;
    if (critical >= 2 || score >= 70) return "F";
    if (critical === 1 || score >= 46) return "D";
    if (score >= 21) return "C";
    if (score > 0) return "B";
    return "A";
  }

  function short(text, limit) {
    const value = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
    const max = limit || 180;
    return value.length <= max ? value : value.slice(0, max - 1) + "\u2026";
  }

  function nowIso() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  function byteLength(text) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text).length;
    return Buffer.byteLength(text, "utf8");
  }

  function loadMcpJson(text) {
    const cleaned = text.replace(/^\uFEFF/, "").trim();
    if (!cleaned) throw new ScanInputError("mcp.json 内容为空：请粘贴完整的 MCP 配置文件。");
    const noComments = cleaned
      .replace(/^\s*\/\/.*$/gm, "")
      .replace(/(?<![:"'])\s\/\/\s.*$/gm, "");
    const noTrailingCommas = noComments.replace(/,(\s*[}\]])/g, "$1");
    const candidates = [cleaned, noComments, noTrailingCommas];
    let lastError = null;
    for (const candidate of candidates) {
      try {
        return JSON.parse(candidate);
      } catch (err) {
        lastError = err;
      }
    }
    throw new ScanInputError("mcp.json 不是合法 JSON（" + (lastError && lastError.message) + "）。");
  }

  function ScanInputError(message) {
    const err = new Error(message);
    err.name = "ScanInputError";
    return err;
  }

  function serversOf(document) {
    if (document === null || typeof document !== "object" || Array.isArray(document)) {
      throw new ScanInputError('mcp.json 顶层必须是对象，例如 {"mcpServers": {...}}。');
    }
    for (const key of ["mcpServers", "servers", "mcp_servers"]) {
      const value = document[key];
      if (value && typeof value === "object" && !Array.isArray(value)) return value;
    }
    const values = Object.values(document);
    if (values.some((v) => v && typeof v === "object" && ("command" in v || "url" in v))) return document;
    throw new ScanInputError('没有找到 mcpServers/servers 节点。期望 {"mcpServers": {"name": {"command": ..., "args": [...]}}}。');
  }

  function serverAction(name) {
    const slug = String(name).toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "");
    return "mcp." + (slug || "server");
  }

  function envValues(server) {
    const out = [];
    const env = server && server.env;
    if (env && typeof env === "object" && !Array.isArray(env)) {
      for (const [key, value] of Object.entries(env)) {
        if (typeof value === "string" || typeof value === "number") out.push([key, String(value)]);
      }
    }
    const headers = server && server.headers;
    if (headers && typeof headers === "object" && !Array.isArray(headers)) {
      for (const [key, value] of Object.entries(headers)) {
        if (typeof value === "string" || typeof value === "number") out.push(["header:" + key, String(value)]);
      }
    }
    return out;
  }

  function scanMcp(text, subject) {
    const document = loadMcpJson(text);
    const servers = serversOf(document);
    const findings = [];
    const capabilities = [];
    const seen = new Set();
    const names = Object.keys(servers);

    function add(ruleId, server, severity, title, detail, evidence, remediation, suggestedRule) {
      const key = ruleId + "\u0000" + server;
      if (seen.has(key) || findings.length >= MAX_FINDINGS) return;
      seen.add(key);
      findings.push({
        id: ruleId,
        severity: severity,
        title: title,
        detail: server ? "[" + server + "] " + detail : detail,
        evidence: short(evidence),
        remediation: remediation,
        suggested_rule: suggestedRule || "",
      });
    }

    const total = names.length;
    if (total >= 12) {
      add("MCP-01", "mcp.json", "low", "接入的 MCP 服务过多，攻击面偏大",
        "共声明 " + total + " 个 MCP 服务，其中任意一个被投毒都会进入 agent 的可信工具面。",
        "server count = " + total,
        "把工具面收敛到当前任务真正需要的服务，其余默认停用。",
        "deny: mcp.*  除非在 allowlist 中显式列出");
    }

    for (const name of names) {
      const raw = servers[name];
      const server = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
      const action = serverAction(name);
      capabilities.push(action);

      const command = String(server.command || "");
      const args = Array.isArray(server.args) ? server.args.map(String) : [];
      const url = String(server.url || "");
      const envItems = envValues(server);
      const envValueList = envItems.map((pair) => pair[1]);
      const blob = [command, ...args, url, ...envValueList].join(" ");
      const auto = server.autoApprove !== undefined ? server.autoApprove : server.alwaysAllow;
      const autoAll = auto === true || (Array.isArray(auto) && auto.some((item) => String(item) === "*"));
      const base = command.replace(/\\/g, "/").split("/").pop().toLowerCase();

      if (autoAll) {
        add("MCP-02", name, "critical", "工具调用被自动批准，没有任何人工或策略确认",
          "autoApprove/alwaysAllow 对全部工具放行，等于把 agent 的决策权直接交给模型输出。",
          JSON.stringify(auto),
          "关闭全量自动批准；改为按工具白名单 + 危险动作强制审批。",
          "deny: " + action + ".*  除非命中显式 allow 规则");
      }

      const shellWithC = SHELLS.has(base) && args.some((a) => ["-c", "/c", "-e", "-command", "-noprofile"].includes(a));
      if (shellWithC) {
        add("MCP-03", name, "critical", "MCP 服务以 shell 解释器 -c 方式启动，等价于任意命令执行",
          "命令字符串由模型或配置拼接，一旦可被影响就是远程命令执行。",
          blob,
          "改为可执行文件直接启动；确需脚本时固定参数、禁止拼接外部输入。",
          "deny: " + action + ".exec");
      } else if (!SHELLS.has(base) && SHELL_TOOLS.test(name)) {
        add("MCP-04", name, "high", "接入了命令/终端类 MCP 服务",
          "该服务的能力面是执行任意命令或脚本，需要独立的审批与沙箱隔离。",
          blob,
          "为命令类服务单独配置策略：只允许白名单命令、超时与工作目录限制。",
          "deny: " + action + ".exec  除非命令在 allowlist");
      }

      for (const pair of envItems) {
        const key = pair[0];
        const value = pair[1];
        if (SECRET_ENV.test(key) && value && !PLACEHOLDER.test(value.trim())) {
          add("MCP-05", name, "critical", "凭据以明文形式写在 mcp.json 的 env/headers 中",
            "环境变量 " + key + " 直接包含真实凭据；该文件通常随项目同步、备份、进日志。",
            '"' + key + '": "' + short(value, 40) + '"',
            "改用运行时注入的环境变量或密钥管理服务；mcp.json 中只保留 ${KEY} 占位符。",
            "deny: mcp.*.secret.read");
        }
      }

      for (const arg of args) {
        const flagMatch = DANGEROUS_FLAGS.exec(arg);
        if (flagMatch) {
          const critical = /privileged|skip-permissions|no-sandbox/i.test(arg);
          add("MCP-06", name, critical ? "critical" : "high", "启动参数关闭了安全边界",
            "参数 " + arg + " 解除沙箱/权限/证书校验，等于让工具运行在无约束环境。",
            arg,
            "移除此类参数；如确需特权，改为独立容器 + 只读挂载 + 最小权限账号。",
            "deny: " + action + ".admin");
        }
      }

      for (let index = 0; index < args.length; index += 1) {
        let value = args[index];
        if (["--root", "--directory", "--dir", "--path"].includes(args[index]) && index + 1 < args.length) {
          value = args[index + 1];
        }
        if (value.toLowerCase() === "#") value = "#";
        if (BROAD_ROOTS.has(value.toLowerCase())) {
          add("MCP-07", name, "critical", "文件系统服务暴露了过宽的根目录",
            "根目录 " + value + " 让 agent 可读写本机任意路径（含凭据、代码、系统文件）。",
            value,
            "把根目录收敛到项目内子目录，并配置只读 + 路径前缀校验。",
            "deny: " + action + ".fs.write");
        }
      }

      if (SECRET_PATHS.test(blob)) {
        add("MCP-08", name, "critical", "工具参数指向 SSH/AWS/凭据目录",
          "该服务可直接读取或修改主机的密钥材料，泄露即等于主机失守。",
          short(blob),
          "禁止 agent 接触 ~/.ssh、~/.aws、.env 等路径；改用短期凭据。",
          "deny: " + action + ".secret.read");
      }

      if (url.toLowerCase().startsWith("http://")) {
        add("MCP-09", name, "high", "远程 MCP 使用明文 HTTP 传输",
          "工具描述与返回内容可被中间人篡改，进而影响 agent 决策（工具投毒）。",
          url,
          "改用 HTTPS 并校验证书；对远程 MCP 增加响应签名/固定哈希。",
          "deny: " + action + ".remote  除非 tls=true");
      }

      const target = [url, ...args, ...envValueList].find((candidate) => DB_URI.test(candidate));
      if (target) {
        add("MCP-10", name, "critical", "数据库连接串内嵌明文口令",
          "agent 一旦能读该配置，就能直连生产库；写权限更会绕过业务规则。",
          target.replace(DB_URI, (m, scheme, user) => scheme + "://" + user + ":***@"),
          "使用 IAM/短期令牌或仅授予只读账号；口令放密钥服务，不放配置。",
          "deny: " + action + ".db.write");
      }

      for (const pair of envItems) {
        if (pair[0].toUpperCase() === "NODE_TLS_REJECT_UNAUTHORIZED" && ["0", "false"].includes(pair[1].trim())) {
          add("MCP-11", name, "high", "关闭了 Node 的 TLS 证书校验",
            "NODE_TLS_REJECT_UNAUTHORIZED=0 使该进程所有 HTTPS 请求都不再验签。",
            pair[0] + "=" + pair[1],
            "移除该变量；如需自签证书，显式传入 CA 而不是关闭校验。",
            "deny: " + action + ".remote");
        }
      }

      if (["npx", "uvx", "bunx", "pnpm"].includes(base)) {
        const packages = args.filter((a) => !a.startsWith("-") && !["run", "dlx", "exec"].includes(a));
        for (const pkg of packages) {
          const match = PINNED.exec(pkg);
          if (match && !match[2]) {
            add("MCP-12", name, "medium", "远程包未锁定版本",
              "「" + pkg + "」每次启动都拉取最新版，供应链投毒会直接进入运行中的 agent。",
              base + " " + args.join(" "),
              "锁定精确版本或 digest，并在 CI 中校验哈希。",
              "deny: " + action + "  除非 package.pinned=true");
            break;
          }
        }
      }

      const hasAuth = envItems.some((pair) => pair[0].toLowerCase() === "authorization");
      if (url && !hasAuth) {
        add("MCP-13", name, "medium", "远程 MCP 未携带认证头",
          "远程 MCP 若无鉴权，任何能访问该地址的人都可以替换工具行为。",
          url,
          "为远程 MCP 增加 Authorization 头或 mTLS，并校验服务端固定公钥。",
          "deny: " + action + ".remote  除非 authenticated=true");
      }

      if (!command && !url) {
        add("MCP-13b", name, "low", "服务条目缺少 command/url",
          "无法确定该条目如何启动，无法纳入策略评估。",
          JSON.stringify(server).slice(0, 120),
          "补全 command 或 url；否则从配置中移除。",
          "");
      }
    }

    const score = severityWeight(findings);
    const grade = gradeFor(score, findings);
    const capabilitiesUnique = Array.from(new Set(capabilities)).sort();
    return {
      kind: "mcp",
      grade: grade,
      score: score,
      subject: subject || "scanned-agent",
      findings: findings,
      capabilities: capabilitiesUnique,
      policy_yaml: renderPolicy({
        subject: subject || "scanned-agent",
        kind: "mcp",
        capabilities: capabilitiesUnique,
        findings: findings,
      }),
      scanned_at: nowIso(),
      stats: { servers: total },
    };
  }

  /* ------------------------------------------------------------------ */
  /* Python static rules — same order and regexes as server/scan.py      */
  /* ------------------------------------------------------------------ */

  const PY_RULES = [
    ["PY-01", "high", /subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^\n]*shell\s*=\s*True/ms,
      "subprocess 以 shell=True 执行命令", "命令字符串交给 shell 解释，任何拼接进命令的模型输出都可以逃逸成任意命令。",
      "改为 shell=False + 参数列表；确需 shell 时使用固定命令白名单。"],
    ["PY-02", "high", /\bos\.(?:system|popen)\s*\(/m,
      "通过 os.system/os.popen 执行外部命令", "该 API 没有参数转义，命令拼接即注入。",
      "改用 subprocess.run(args, shell=False)，并校验参数来源。"],
    ["PY-03", "high", /\b(?:eval|exec)\s*\(/m,
      "动态执行模型/用户可控的代码", "eval/exec 会把字符串当代码运行，等于把执行权交给输入方。",
      "改为显式解析（ast.literal_eval 或 JSON schema），禁止执行字符串代码。"],
    ["PY-04", "high", /\bpickle\.(?:loads|load)\s*\(/m,
      "反序列化不可信的 pickle 数据", "pickle 反序列化可执行任意代码，是典型的 RCE 入口。",
      "改用 JSON 或显式 schema；必须兼容旧数据时加签名与来源校验。"],
    ["PY-05", "critical", /(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})/m,
      "源码中硬编码了真实凭据", "密钥进入源码就会进入 git 历史、日志与备份；轮换成本远高于一次性修复。",
      "立即轮换该密钥，改用环境变量或密钥管理服务；加入 secret 扫描门禁。"],
    ["PY-06", "high", /verify\s*=\s*False|\bssl\._create_unverified_context\b/m,
      "关闭了 HTTPS 证书校验", "关闭校验后，工具返回内容可被中间人替换，进而篡改 agent 行为。",
      "恢复证书校验；自建 CA 时显式传入 CA 包而非关闭校验。"],
    ["PY-07", "medium", /requests\.(?:get|post|put|patch|delete)\s*\(\s*['"]http:\/\//m,
      "以明文 HTTP 调用外部接口", "请求与响应都可被窃听或篡改。",
      "改用 HTTPS，并对返回内容做来源与格式校验。"],
    ["PY-08", "high", /(?:cursor|conn)\.execute\s*\(\s*f?['"][^'"]*(?:\{[^}]*\}|%s[^'"]*%|['"]\s*\+)/m,
      "SQL 由字符串拼接/f-string 构造", "用户或模型可控的输入进入 SQL，存在注入与越权读写风险。",
      "改用参数化查询；数据库账号最小权限且只读为主。"],
    ["PY-09", "medium", /\b(?:shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(/m,
      "代码可以删除文件或目录", "删除动作若作用于用户可控路径，可能造成不可逆数据丢失。",
      "限制删除根目录到工作区，先移动到回收站/软删除并留审计记录。"],
    ["PY-10", "medium", /\b__import__\s*\(|importlib\.import_module\s*\(/m,
      "动态导入模块", "模块名可控时等于加载任意代码。",
      "使用固定模块注册表，禁止外部输入决定导入目标。"],
    ["PY-11", "medium", /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/m,
      "CORS 允许任意来源", "任意网页都可带着用户会话调用该服务。",
      "收敛到明确的前端域名列表，并配合 CSRF 防护。"],
    ["PY-12", "low", /except\s*(?:Exception)?\s*:\s*\n\s*pass\b/m,
      "异常被静默吞掉", "失败被当作成功继续执行，agent 动作的审计链会缺失关键节点。",
      "记录异常并转为显式 HALT/DENY 决策，不要静默 pass。"],
    ["PY-13", "medium", /\bos\.environ\s*\[[^\]]+\]\s*=/m,
      "运行时改写进程环境变量", "可能覆盖凭据或代理配置，影响最终执行环境。",
      "只在启动时注入配置，运行期禁止修改关键环境变量。"],
    ["PY-14", "low", /open\s*\([^)]*['"][wa]b?['"]\)/m,
      "代码可写入文件", "写路径若来自模型输出，可能覆盖配置或写入启动项。",
      "写入限制在工作区沙箱内，并对路径做规范化与白名单校验。"],
    ["PY-15", "medium", /\bsocket\.(?:socket|create_connection)\s*\(/m,
      "代码可发起任意 TCP 连接", "可绕过 HTTP 出口代理与审计，形成隐蔽通道。",
      "统一走受控 HTTP 客户端与出口代理，限制目标地址。"],
  ];

  const PY_SUGGESTIONS = {
    "PY-01": "deny: tool.shell.exec（shell=True）",
    "PY-02": "deny: tool.shell.exec",
    "PY-03": "deny: tool.code.eval",
    "PY-04": "deny: tool.data.deserialize（仅允许 json）",
    "PY-05": "deny: tool.secret.read；轮换密钥",
    "PY-06": "deny: tool.http.request 除非 tls_verify=true",
    "PY-07": "deny: tool.http.request 除非 scheme=https",
    "PY-08": "deny: tool.db.write；只读参数化查询",
    "PY-09": "deny: tool.fs.delete",
    "PY-10": "deny: tool.code.dynamic_import",
    "PY-11": "deny: tool.http.cors.*",
    "PY-12": "require: on_error = HALT",
    "PY-13": "deny: tool.env.write",
    "PY-14": "deny: tool.fs.write 除非 path 在 workspace",
    "PY-15": "deny: tool.network.raw_socket",
    "PY-16": "require: pre_action_signed_receipt = true",
    "PY-17": "deny: tool.command.* 除非 command in allowlist",
  };

  function scanPython(text, subject) {
    const code = text.replace(/^\uFEFF/, "");
    if (!code.trim()) throw new ScanInputError("Python 代码为空：请粘贴 agent 工具函数源码。");
    const findings = [];
    const capabilities = [];

    for (const rule of PY_RULES) {
      const ruleId = rule[0];
      const severity = rule[1];
      const pattern = rule[2];
      const title = rule[3];
      const detail = rule[4];
      const remediation = rule[5];
      pattern.lastIndex = 0;
      const match = pattern.exec(code);
      if (!match) continue;
      const lineNo = code.slice(0, match.index).split("\n").length;
      const snippet = match[0].replace(/\n/g, " ");
      findings.push({
        id: ruleId,
        severity: severity,
        title: title,
        detail: detail,
        evidence: "L" + lineNo + ": " + short(snippet, 140),
        remediation: remediation,
        suggested_rule: PY_SUGGESTIONS[ruleId] || "",
      });
    }

    const toolDefs = (code.match(/^\s*@(?:tool|function_tool|mcp\.tool|app\.tool)\b/gm) || []).length;
    const hasPolicy = /(agentproof|policy|Policy\b|require_approval|guardrail|allowlist)/i.test(code);
    if (toolDefs && !hasPolicy) {
      findings.push({
        id: "PY-16",
        severity: "high",
        title: "发现 " + toolDefs + " 个工具定义，但没有接入策略门",
        detail: "工具函数直接暴露给模型，动作执行前没有 allow/deny 判定，也没有签名回执。",
        evidence: "tool decorators: " + toolDefs + ", policy references: 0",
        remediation: "在工具调用入口接入 policy gate：默认拒绝，命中规则且所有前置条件满足才放行，并签发回执。",
        suggested_rule: PY_SUGGESTIONS["PY-16"],
      });
    }
    const commandDef = /def\s+\w*(?:shell|exec|command|run_cmd)\w*\s*\([^)]*\)/i.exec(code);
    if (commandDef) {
      findings.push({
        id: "PY-17",
        severity: "high",
        title: "存在命令执行类工具函数",
        detail: "该函数把 agent 的意图直接转成系统命令，需要单独的最小权限与审批策略。",
        evidence: short(commandDef[0], 180),
        remediation: "命令执行工具只允许白名单命令，禁止透传模型生成的任意字符串。",
        suggested_rule: PY_SUGGESTIONS["PY-17"],
      });
    }

    const definitions = code.match(/^\s*def\s+(\w+)\s*\(/gm) || [];
    for (const line of definitions) {
      const name = line.replace(/^\s*def\s+/, "").replace(/\s*\($/, "");
      if (name.startsWith("_") || ["__init__", "main"].includes(name)) continue;
      capabilities.push("tool." + name);
    }

    findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || a.id.localeCompare(b.id));
    const score = severityWeight(findings);
    const grade = gradeFor(score, findings);
    const capabilitiesUnique = Array.from(new Set(capabilities)).sort();
    return {
      kind: "python",
      grade: grade,
      score: score,
      subject: subject || "scanned-agent",
      findings: findings,
      capabilities: capabilitiesUnique,
      policy_yaml: renderPolicy({
        subject: subject || "scanned-agent",
        kind: "python",
        capabilities: capabilitiesUnique,
        findings: findings,
      }),
      scanned_at: nowIso(),
      stats: { tool_definitions: capabilities.length, lines: code.split("\n").length },
    };
  }

  /* ------------------------------------------------------------------ */
  /* policy.yaml rendering — byte-compatible with server/scan.py         */
  /* ------------------------------------------------------------------ */

  function yamlScalar(value) {
    const text = String(value);
    if (text === "") return '""';
    if (/[:#\[\]{}&*!|>'"%@`,\n]/.test(text) || text.trim() !== text) return JSON.stringify(text);
    return text;
  }

  function actionFromRule(rule) {
    const match = /(?:deny|allow):\s*([A-Za-z0-9_.*]+)/.exec(rule || "");
    return match ? match[1] : "";
  }

  function renderPolicy(options) {
    const subject = options.subject;
    const kind = options.kind;
    const capabilities = options.capabilities;
    const findings = options.findings;
    const lines = [];
    lines.push("# Generated by AgentProof.cloud scanner");
    lines.push("# source-kind: " + kind);
    lines.push("# subject: " + yamlScalar(subject));
    lines.push("# policy: deny by default \u2014 no rule match means DENY");
    lines.push("version: 1");
    lines.push("subject: " + yamlScalar(subject));
    lines.push("mode: enforce");
    lines.push("");
    lines.push("capabilities:");
    if (capabilities.length) {
      for (const capability of capabilities) lines.push("  - name: " + yamlScalar(capability));
    } else {
      lines.push("  - name: tool.read");
    }
    lines.push("");
    lines.push("rules:");
    const critical = findings.filter((f) => f.severity === "critical").length;
    if (critical === 0) {
      lines.push("  - id: allow-readonly-tools");
      lines.push('    action: "*"');
      lines.push("    effect: allow");
      lines.push("    reason: Read-only tool surface, no critical findings");
      lines.push("    conditions:");
      lines.push("      max_input_bytes: 65536");
      lines.push('      required_scopes: ["read"]');
      lines.push("      read_only: true");
    } else {
      lines.push("  - id: allow-readonly-tools");
      lines.push('    action: "tool.read.*"');
      lines.push("    effect: allow");
      lines.push("    reason: Only explicitly read-only tools are pre-approved");
      lines.push("    conditions:");
      lines.push("      max_input_bytes: 32768");
    }
    const seenActions = new Set();
    for (const finding of findings) {
      const action = actionFromRule(finding.suggested_rule);
      if (!action || seenActions.has(action)) continue;
      seenActions.add(action);
      const id = "deny-" + action.replace(/\*/g, "x").replace(/\./g, "-").replace(/_/g, "-");
      lines.push("  - id: " + id);
      lines.push("    action: " + yamlScalar(action));
      lines.push("    effect: deny");
      lines.push("    reason: " + yamlScalar(finding.title));
    }
    lines.push("");
    lines.push("  - id: deny-default");
    lines.push('    action: "*"');
    lines.push("    effect: deny");
    lines.push("    reason: Default deny \u2014 no matching allow rule");
    lines.push("");
    lines.push("audit:");
    lines.push("  ledger: hash-chain+ed25519");
    lines.push("  sign_before_action: true");
    lines.push("  seal_interval: 100");
    lines.push("  require_receipt: true");
    lines.push("");
    return lines.join("\n");
  }

  function scan(kind, content, options) {
    const subject = (options && options.subject) || "scanned-agent";
    const text = String(content == null ? "" : content);
    if (byteLength(text) > MAX_CONTENT_BYTES) {
      throw new ScanInputError("输入超过 " + Math.floor(MAX_CONTENT_BYTES / 1000) + " KB 上限。请只提交相关的 mcp.json 或工具代码片段。");
    }
    const normalized = String(kind || "mcp").toLowerCase();
    if (["mcp", "mcp.json", "mcp_config"].includes(normalized)) return scanMcp(text, subject);
    if (["python", "py", "python_code"].includes(normalized)) return scanPython(text, subject);
    throw new ScanInputError("kind 必须是 mcp 或 python。");
  }

  const SAMPLES = {
    dangerMcp: `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "autoApprove": true
    },
    "shell": {
      "command": "bash",
      "args": ["-c", "npx -y mcp-server-shell@latest"],
      "env": {
        "OPENAI_API_KEY": "sk-proj-9f3a2c1d8e7b6a5c4d3e2f1a",
        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
      }
    },
    "prod-db": {
      "command": "npx",
      "args": ["-y", "mcp-server-postgres@latest"],
      "env": {
        "DATABASE_URL": "postgres://ops_admin:Pr0d%21Pass@db.prod.internal:5432/billing"
      }
    },
    "remote-kb": {
      "url": "http://kb.internal:8080/mcp",
      "type": "http"
    }
  }
}`,
    safeMcp: `{
  "mcpServers": {
    "kb-search": {
      "command": "npx",
      "args": ["-y", "@acme/mcp-kb@1.4.2", "--root", "./workspace/kb"],
      "env": {
        "KB_TOKEN": "\${KB_TOKEN}"
      }
    }
  }
}`,
    python: `import os
import subprocess
import requests

@tool
def run_shell(command: str) -> str:
    """执行任意命令。"""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()

@tool
def evaluate(expression: str):
    return eval(expression)

@tool
def refund(order_id: str, amount: float) -> dict:
    if amount > 500:
        return {"error": "manual review"}
    requests.post("http://payments.internal/refund", json={"order": order_id, "amount": amount}, verify=False)
    cursor = db.cursor()
    cursor.execute(f"UPDATE orders SET refunded=1 WHERE id={order_id}")
    os.remove("/var/agent/refund-journal.log")
    return {"ok": True}

@tool
def search(q: str) -> list:
    return kb.search(q, limit=5)

OPENAI_API_KEY = "sk-proj-7d1f9a2b3c4d5e6f7a8b9c0d"

app.add_middleware(CORSMiddleware, allow_origins=["*"])
`,
  };

  return {
    scan: scan,
    scanMcp: scanMcp,
    scanPython: scanPython,
    renderPolicy: renderPolicy,
    samples: SAMPLES,
    gradeFor: gradeFor,
    ScanInputError: ScanInputError,
    EMAIL_RE: EMAIL_RE,
  };
});

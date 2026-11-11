"""Static risk analysis for MCP server configs and Python agent tool code.

Pure functions, no I/O, deterministic: the same input always produces the same
findings, the same score, and the same generated ``policy.yaml``. The
AgentProof.cloud API serves this module; ``site/assets/app.js`` contains a
browser port used only for the offline preview mode.

The analysis is static and deliberately conservative. It reports what the
configuration *and code allow an agent to do*, not what it did.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

__all__ = [
    "Finding",
    "ScanResult",
    "ScanInputError",
    "scan",
    "scan_mcp",
    "scan_python",
    "MAX_CONTENT_BYTES",
]

MAX_CONTENT_BYTES = 200_000

SEVERITY_WEIGHT = {"critical": 40, "high": 18, "medium": 8, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
GRADE_ORDER = ["A", "B", "C", "D", "F"]


class ScanInputError(ValueError):
    """The submitted document cannot be parsed at all."""


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    evidence: str
    remediation: str
    suggested_rule: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    kind: str
    grade: str
    score: int
    subject: str
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    policy_yaml: str = ""
    scanned_at: str = ""
    stats: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "kind": self.kind,
            "grade": self.grade,
            "score": self.score,
            "subject": self.subject,
            "findings": [f.as_dict() for f in self.findings],
            "capabilities": self.capabilities,
            "policy_yaml": self.policy_yaml,
            "scanned_at": self.scanned_at,
            "stats": {
                **self.stats,
                "finding_counts": counts,
                "total_findings": len(self.findings),
            },
        }


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_SECRET_ENV = re.compile(
    r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|_KEY)$",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"^(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|x{3,}|\*{3,}|changeme|your[_-].*|placeholder|todo)$",
    re.IGNORECASE,
)
_DB_URI = re.compile(
    r"^(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://([^:@/\s]+):([^@/\s]+)@",
    re.IGNORECASE,
)
_SHELLS = {
    "sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell",
    "powershell.exe", "pwsh", "pwsh.exe", "cscript", "wscript", "osascript",
}
_SHELL_TOOLS = re.compile(
    r"(?:^|[^a-z])(shell|command|exec|terminal|subprocess|run[-_]?command|system)(?:$|[^a-z])",
    re.IGNORECASE,
)
_BROAD_ROOTS = {"/", "\\", "c:\\", "c:/", "~", "$home", "%userprofile%", "**", "*", "..", "../", "/root", "/home"}
_SECRET_PATHS = re.compile(
    r"(\.ssh|\.aws|\.gnupg|\.env\b|id_rsa|id_ed25519|\.git/config|\.kube|\.docker/config|credentials|secrets?)",
    re.IGNORECASE,
)
_DANGEROUS_FLAGS = re.compile(
    r"(--dangerously[a-z-]*|--no-sandbox|--disable-web-security|--allow-(?:all|root|write|exec)"
    r"|--enable-all|--privileged|--net[= ]host|--insecure|--tls-verify[= ]false"
    r"|-v\s+/:/host|--cap-add[= ]SYS_ADMIN)",
    re.IGNORECASE,
)
_PINNED = re.compile(r"^(@?[^@/\s]+)(?:@([^/\s]+))?$")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _short(text: str, limit: int = 180) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _load_mcp_json(text: str) -> Any:
    """Parse MCP JSON, tolerating BOM, // comments and trailing commas."""
    cleaned = text.lstrip("\ufeff").strip()
    if not cleaned:
        raise ScanInputError("mcp.json 内容为空：请粘贴完整的 MCP 配置文件。")
    candidates = [cleaned]
    without_comments = re.sub(r"(?m)^\s*//.*$", "", cleaned)
    without_comments = re.sub(r"(?<![:\"'])\s//\s.*$", "", without_comments)
    candidates.append(without_comments)
    candidates.append(re.sub(r",(\s*[}\]])", r"\1", without_comments))
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
    raise ScanInputError(
        f"mcp.json 不是合法 JSON（{last_error}）。第 {getattr(last_error, 'lineno', '?')} 行"
        f"第 {getattr(last_error, 'colno', '?')} 列附近。"
    )


def _servers(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ScanInputError("mcp.json 顶层必须是对象，例如 {\"mcpServers\": {...}}。")
    for key in ("mcpServers", "servers", "mcp_servers"):
        value = document.get(key)
        if isinstance(value, dict):
            return value
    if any(isinstance(v, dict) and ("command" in v or "url" in v) for v in document.values()):
        # some clients omit the wrapper and list servers at the top level
        return document  # type: ignore[return-value]
    raise ScanInputError(
        '没有找到 mcpServers/servers 节点。期望 {"mcpServers": {"name": {"command": ..., "args": [...]}}}。'
    )


def _server_actions(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", ".", name.lower()).strip(".") or "server"
    return f"mcp.{slug}"


def _is_local_url(url: str) -> bool:
    """True for loopback / dev-server URLs, where plain HTTP is normal."""
    try:
        from urllib.parse import urlparse

        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or host.endswith(".localhost")


def _env_values(server: dict[str, Any]) -> Iterable[tuple[str, str]]:
    env = server.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            if isinstance(value, (str, int, float)):
                yield str(key), str(value)
    headers = server.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if isinstance(value, (str, int, float)):
                yield f"header:{key}", str(value)


# ---------------------------------------------------------------------------
# MCP config analysis
# ---------------------------------------------------------------------------


def scan_mcp(text: str, *, subject: str = "scanned-agent") -> ScanResult:
    document = _load_mcp_json(text)
    servers = _servers(document)
    findings: list[Finding] = []
    capabilities: list[str] = []
    seen: set[tuple[str, str]] = set()

    def add(
        rule_id: str,
        server: str,
        severity: str,
        title: str,
        detail: str,
        evidence: str,
        remediation: str,
        suggested_rule: str = "",
    ) -> None:
        key = (rule_id, server)
        if key in seen or len(findings) >= 14:
            return
        seen.add(key)
        findings.append(
            Finding(
                id=f"{rule_id}",
                severity=severity,
                title=title,
                detail=f"[{server}] {detail}" if server else detail,
                evidence=_short(evidence),
                remediation=remediation,
                suggested_rule=suggested_rule,
            )
        )

    total = len(servers)
    if total >= 12:
        add(
            "MCP-01",
            "mcp.json",
            "low",
            "接入的 MCP 服务过多，攻击面偏大",
            f"共声明 {total} 个 MCP 服务，其中任意一个被投毒都会进入 agent 的可信工具面。",
            f"server count = {total}",
            "把工具面收敛到当前任务真正需要的服务，其余默认停用。",
            "deny: mcp.*  除非在 allowlist 中显式列出",
        )

    for name, raw_server in servers.items():
        server: dict[str, Any] = raw_server if isinstance(raw_server, dict) else {}
        action = _server_actions(name)
        capabilities.append(action)

        command = str(server.get("command") or "")
        args_raw = server.get("args")
        args = [str(a) for a in args_raw] if isinstance(args_raw, list) else []
        url = str(server.get("url") or "")
        env_items = list(_env_values(server))
        env_values = [value for _key, value in env_items]
        blob = " ".join([command, *args, url, *env_values])
        auto = server.get("autoApprove", server.get("alwaysAllow", False))
        auto_all = auto is True or (isinstance(auto, list) and any(str(a) == "*" for a in auto))
        exec_blob = " ".join(p for p in [command.split("\\")[-1].split("/")[-1], *args])

        # MCP-02 auto approve everything
        if auto_all:
            add(
                "MCP-02",
                name,
                "critical",
                "工具调用被自动批准，没有任何人工或策略确认",
                "autoApprove/alwaysAllow 对全部工具放行，等于把 agent 的决策权直接交给模型输出。",
                json.dumps(auto, ensure_ascii=False),
                "关闭全量自动批准；改为按工具白名单 + 危险动作强制审批。",
                f"deny: {action}.*  除非命中显式 allow 规则",
            )

        # MCP-03 shell interpreter with -c
        base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in _SHELLS and any(a in {"-c", "/c", "-e", "-command", "-noprofile"} for a in args):
            add(
                "MCP-03",
                name,
                "critical",
                "MCP 服务以 shell 解释器 -c 方式启动，等价于任意命令执行",
                "命令字符串由模型或配置拼接，一旦可被影响就是远程命令执行。",
                blob,
                "改为可执行文件直接启动；确需脚本时固定参数、禁止拼接外部输入。",
                f"deny: {action}.exec",
            )

        # MCP-04 shell-like server
        elif _SHELL_TOOLS.search(name) and not base in _SHELLS:
            add(
                "MCP-04",
                name,
                "high",
                "接入了命令/终端类 MCP 服务",
                "该服务的能力面是执行任意命令或脚本，需要独立的审批与沙箱隔离。",
                blob,
                "为命令类服务单独配置策略：只允许白名单命令、超时与工作目录限制。",
                f"deny: {action}.exec  除非命令在 allowlist",
            )

        # MCP-05 secrets in env/headers
        for key, value in _env_values(server):
            if _SECRET_ENV.search(key) and value and not _PLACEHOLDER.match(value.strip()):
                add(
                    "MCP-05",
                    name,
                    "critical",
                    "凭据以明文形式写在 mcp.json 的 env/headers 中",
                    f"环境变量 {key} 直接包含真实凭据；该文件通常随项目同步、备份、进日志。",
                    f'"{key}": "{_short(value, 40)}"',
                    "改用运行时注入的环境变量或密钥管理服务；mcp.json 中只保留 ${KEY} 占位符。",
                    "deny: mcp.*.secret.read",
                )

        # MCP-06 dangerous flags
        for arg in args:
            if _DANGEROUS_FLAGS.search(arg):
                severity = "critical" if re.search(r"privileged|skip-permissions|no-sandbox", arg, re.I) else "high"
                add(
                    "MCP-06",
                    name,
                    severity,
                    "启动参数关闭了安全边界",
                    f"参数 {arg} 解除沙箱/权限/证书校验，等于让工具运行在无约束环境。",
                    arg,
                    "移除此类参数；如确需特权，改为独立容器 + 只读挂载 + 最小权限账号。",
                    f"deny: {action}.admin",
                )

        # MCP-07 broad filesystem roots
        roots: list[str] = []
        for index, arg in enumerate(args):
            value = arg
            if arg in {"--root", "--directory", "--dir", "--path"} and index + 1 < len(args):
                value = args[index + 1]
            if value.startswith("#") or value.lower() in _BROAD_ROOTS:
                roots.append(value)
            if value.lower() in _BROAD_ROOTS:
                add(
                    "MCP-07",
                    name,
                    "critical",
                    "文件系统服务暴露了过宽的根目录",
                    f"根目录 {value} 让 agent 可读写本机任意路径（含凭据、代码、系统文件）。",
                    value,
                    "把根目录收敛到项目内子目录，并配置只读 + 路径前缀校验。",
                    f"deny: {action}.fs.write",
                )

        # MCP-08 secret paths
        if _SECRET_PATHS.search(blob):
            add(
                "MCP-08",
                name,
                "critical",
                "工具参数指向 SSH/AWS/凭据目录",
                "该服务可直接读取或修改主机的密钥材料，泄露即等于主机失守。",
                _short(blob),
                "禁止 agent 接触 ~/.ssh、~/.aws、.env 等路径；改用短期凭据。",
                f"deny: {action}.secret.read",
            )

        # MCP-09 plain http transport
        if url.lower().startswith("http://") and not _is_local_url(url):
            add(
                "MCP-09",
                name,
                "high",
                "远程 MCP 使用明文 HTTP 传输",
                "工具描述与返回内容可被中间人篡改，进而影响 agent 决策（工具投毒）。",
                url,
                "改用 HTTPS 并校验证书；对远程 MCP 增加响应签名/固定哈希。",
                f"deny: {action}.remote  除非 tls=true",
            )

        # MCP-10 DB URI with password
        target = next((a for a in [url, *args, *env_values] if _DB_URI.match(a)), "")
        if target:
            add(
                "MCP-10",
                name,
                "critical",
                "数据库连接串内嵌明文口令",
                "agent 一旦能读该配置，就能直连生产库；写权限更会绕过业务规则。",
                _DB_URI.sub(lambda m: f"{m.group(1)}://{m.group(2)}:***@", target),
                "使用 IAM/短期令牌或仅授予只读账号；口令放密钥服务，不放配置。",
                f"deny: {action}.db.write",
            )

        # MCP-11 TLS verification disabled
        for key, value in _env_values(server):
            if key.upper() == "NODE_TLS_REJECT_UNAUTHORIZED" and value.strip() in {"0", "false"}:
                add(
                    "MCP-11",
                    name,
                    "high",
                    "关闭了 Node 的 TLS 证书校验",
                    "NODE_TLS_REJECT_UNAUTHORIZED=0 使该进程所有 HTTPS 请求都不再验签。",
                    f"{key}={value}",
                    "移除该变量；如需自签证书，显式传入 CA 而不是关闭校验。",
                    f"deny: {action}.remote",
                )

        # MCP-12 unpinned remote package
        if base in {"npx", "uvx", "bunx", "pnpm"}:
            packages = [a for a in args if not a.startswith("-") and a not in {"run", "dlx", "exec"}]
            for package in packages:
                match = _PINNED.match(package)
                if match and not match.group(2):
                    add(
                        "MCP-12",
                        name,
                        "medium",
                        "远程包未锁定版本",
                        f"「{package}」每次启动都拉取最新版，供应链投毒会直接进入运行中的 agent。",
                        f"{base} {' '.join(args)}",
                        "锁定精确版本或 digest，并在 CI 中校验哈希。",
                        f"deny: {action}  除非 package.pinned=true",
                    )
                    break

        # MCP-13 remote server with no auth header
        if url and not _is_local_url(url) and not any(k.lower() == "authorization" for k, _ in _env_values(server)):
            add(
                "MCP-13",
                name,
                "medium",
                "远程 MCP 未携带认证头",
                "远程 MCP 若无鉴权，任何能访问该地址的人都可以替换工具行为。",
                url,
                "为远程 MCP 增加 Authorization 头或 mTLS，并校验服务端固定公钥。",
                f"deny: {action}.remote  除非 authenticated=true",
            )

        if not command and not url:
            add(
                "MCP-13b",
                name,
                "low",
                "服务条目缺少 command/url",
                "无法确定该条目如何启动，无法纳入策略评估。",
                json.dumps(server, ensure_ascii=False)[:120],
                "补全 command 或 url；否则从配置中移除。",
                "",
            )

    score = _score(findings)
    grade = _grade(score, findings)
    policy = _render_policy(
        subject=subject,
        kind="mcp",
        capabilities=sorted(set(capabilities)),
        findings=findings,
    )
    return ScanResult(
        kind="mcp",
        grade=grade,
        score=score,
        subject=subject,
        findings=findings,
        capabilities=sorted(set(capabilities)),
        policy_yaml=policy,
        scanned_at=_now(),
        stats={"servers": total},
    )


# ---------------------------------------------------------------------------
# Python agent tool code analysis
# ---------------------------------------------------------------------------

_PY_RULES: list[tuple[str, str, str, str, str, str]] = [
    # id, severity, pattern, title, detail, remediation
    (
        "PY-01",
        "high",
        r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^\n]*shell\s*=\s*True",
        "subprocess 以 shell=True 执行命令",
        "命令字符串交给 shell 解释，任何拼接进命令的模型输出都可以逃逸成任意命令。",
        "改为 shell=False + 参数列表；确需 shell 时使用固定命令白名单。",
    ),
    (
        "PY-02",
        "high",
        r"\bos\.(?:system|popen)\s*\(",
        "通过 os.system/os.popen 执行外部命令",
        "该 API 没有参数转义，命令拼接即注入。",
        "改用 subprocess.run(args, shell=False)，并校验参数来源。",
    ),
    (
        "PY-03",
        "high",
        r"\b(?:eval|exec)\s*\(",
        "动态执行模型/用户可控的代码",
        "eval/exec 会把字符串当代码运行，等于把执行权交给输入方。",
        "改为显式解析（ast.literal_eval 或 JSON schema），禁止执行字符串代码。",
    ),
    (
        "PY-04",
        "high",
        r"\bpickle\.(?:loads|load)\s*\(",
        "反序列化不可信的 pickle 数据",
        "pickle 反序列化可执行任意代码，是典型的 RCE 入口。",
        "改用 JSON 或显式 schema；必须兼容旧数据时加签名与来源校验。",
    ),
    (
        "PY-05",
        "critical",
        r"(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})",
        "源码中硬编码了真实凭据",
        "密钥进入源码就会进入 git 历史、日志与备份；轮换成本远高于一次性修复。",
        "立即轮换该密钥，改用环境变量或密钥管理服务；加入 secret 扫描门禁。",
    ),
    (
        "PY-06",
        "high",
        r"verify\s*=\s*False|\bssl\._create_unverified_context\b",
        "关闭了 HTTPS 证书校验",
        "关闭校验后，工具返回内容可被中间人替换，进而篡改 agent 行为。",
        "恢复证书校验；自建 CA 时显式传入 CA 包而非关闭校验。",
    ),
    (
        "PY-07",
        "medium",
        r"requests\.(?:get|post|put|patch|delete)\s*\(\s*['\"]http://",
        "以明文 HTTP 调用外部接口",
        "请求与响应都可被窃听或篡改。",
        "改用 HTTPS，并对返回内容做来源与格式校验。",
    ),
    (
        "PY-08",
        "high",
        r"(?:cursor|conn)\.execute\s*\(\s*f?['\"][^'\"]*(?:\{[^}]*\}|%s[^'\"]*%|['\"]\s*\+)",
        "SQL 由字符串拼接/f-string 构造",
        "用户或模型可控的输入进入 SQL，存在注入与越权读写风险。",
        "改用参数化查询；数据库账号最小权限且只读为主。",
    ),
    (
        "PY-09",
        "medium",
        r"\b(?:shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(",
        "代码可以删除文件或目录",
        "删除动作若作用于用户可控路径，可能造成不可逆数据丢失。",
        "限制删除根目录到工作区，先移动到回收站/软删除并留审计记录。",
    ),
    (
        "PY-10",
        "medium",
        r"\b__import__\s*\(|importlib\.import_module\s*\(",
        "动态导入模块",
        "模块名可控时等于加载任意代码。",
        "使用固定模块注册表，禁止外部输入决定导入目标。",
    ),
    (
        "PY-11",
        "medium",
        r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        "CORS 允许任意来源",
        "任意网页都可带着用户会话调用该服务。",
        "收敛到明确的前端域名列表，并配合 CSRF 防护。",
    ),
    (
        "PY-12",
        "low",
        r"except\s*(?:Exception)?\s*:\s*\n\s*pass\b",
        "异常被静默吞掉",
        "失败被当作成功继续执行，agent 动作的审计链会缺失关键节点。",
        "记录异常并转为显式 HALT/DENY 决策，不要静默 pass。",
    ),
    (
        "PY-13",
        "medium",
        r"\bos\.environ\s*\[[^\]]+\]\s*=",
        "运行时改写进程环境变量",
        "可能覆盖凭据或代理配置，影响最终执行环境。",
        "只在启动时注入配置，运行期禁止修改关键环境变量。",
    ),
    (
        "PY-14",
        "low",
        r"open\s*\([^)]*['\"][wa]b?['\"]\)",
        "代码可写入文件",
        "写路径若来自模型输出，可能覆盖配置或写入启动项。",
        "写入限制在工作区沙箱内，并对路径做规范化与白名单校验。",
    ),
    (
        "PY-15",
        "medium",
        r"\bsocket\.(?:socket|create_connection)\s*\(",
        "代码可发起任意 TCP 连接",
        "可绕过 HTTP 出口代理与审计，形成隐蔽通道。",
        "统一走受控 HTTP 客户端与出口代理，限制目标地址。",
    ),
]


def scan_python(text: str, *, subject: str = "scanned-agent") -> ScanResult:
    code = text.lstrip("\ufeff")
    if not code.strip():
        raise ScanInputError("Python 代码为空：请粘贴 agent 工具函数源码。")
    findings: list[Finding] = []
    capacities: list[str] = []
    compiled: list[tuple[tuple[str, str, str, str, str, str], re.Pattern[str]]] = [
        (rule, re.compile(rule[2], re.MULTILINE | re.DOTALL)) for rule in _PY_RULES
    ]

    for rule, pattern in compiled:
        match = pattern.search(code)
        if not match:
            continue
        rule_id, severity, _pattern, title, detail, remediation = rule
        line_no = code[: match.start()].count("\n") + 1
        snippet = match.group(0).replace("\n", " ")
        findings.append(
            Finding(
                id=rule_id,
                severity=severity,
                title=title,
                detail=detail,
                evidence=f"L{line_no}: {_short(snippet, 140)}",
                remediation=remediation,
                suggested_rule=_python_rule(rule_id),
            )
        )

    # tool surface / policy gate presence
    tool_defs = re.findall(r"^\s*@(?:tool|function_tool|mcp\.tool|app\.tool)\b", code, re.MULTILINE)
    has_policy = bool(
        re.search(r"(agentproof|policy|Policy\b|require_approval|guardrail|allowlist)", code, re.IGNORECASE)
    )
    if tool_defs and not has_policy:
        findings.append(
            Finding(
                id="PY-16",
                severity="high",
                title=f"发现 {len(tool_defs)} 个工具定义，但没有接入策略门",
                detail="工具函数直接暴露给模型，动作执行前没有 allow/deny 判定，也没有签名回执。",
                evidence=f"tool decorators: {len(tool_defs)}, policy references: 0",
                remediation="在工具调用入口接入 policy gate：默认拒绝，命中规则且所有前置条件满足才放行，并签发回执。",
                suggested_rule="require: pre_action_signed_receipt = true",
            )
        )
    if re.search(r"def\s+\w*(?:shell|exec|command|run_cmd)\w*\s*\(", code, re.IGNORECASE):
        findings.append(
            Finding(
                id="PY-17",
                severity="high",
                title="存在命令执行类工具函数",
                detail="该函数把 agent 的意图直接转成系统命令，需要单独的最小权限与审批策略。",
                evidence=_short(re.search(r"def\s+\w*(?:shell|exec|command|run_cmd)\w*\s*\([^)]*\)", code, re.IGNORECASE).group(0)),
                remediation="命令执行工具只允许白名单命令，禁止透传模型生成的任意字符串。",
                suggested_rule="deny: tool.command.*  除非 command in allowlist",
            )
        )

    for match in re.finditer(r"^\s*def\s+(\w+)\s*\(", code, re.MULTILINE):
        name = match.group(1)
        if name.startswith("_") or name in {"__init__", "main"}:
            continue
        capacities.append(f"tool.{name}")

    # deterministic ordering: severity, then id
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id))
    score = _score(findings)
    grade = _grade(score, findings)
    policy = _render_policy(
        subject=subject,
        kind="python",
        capabilities=sorted(set(capacities)),
        findings=findings,
    )
    return ScanResult(
        kind="python",
        grade=grade,
        score=score,
        subject=subject,
        findings=findings,
        capabilities=sorted(set(capacities)),
        policy_yaml=policy,
        scanned_at=_now(),
        stats={"tool_definitions": len(capacities), "lines": code.count("\n") + 1},
    )


def _python_rule(rule_id: str) -> str:
    return {
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
    }.get(rule_id, "")


# ---------------------------------------------------------------------------
# scoring / policy rendering
# ---------------------------------------------------------------------------


def _score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))


def _grade(score: int, findings: list[Finding]) -> str:
    critical = sum(1 for f in findings if f.severity == "critical")
    if critical >= 2 or score >= 70:
        return "F"
    if critical == 1 or score >= 46:
        return "D"
    if score >= 21:
        return "C"
    if score > 0:
        return "B"
    return "A"


def _yaml_scalar(value: str) -> str:
    if value == "":
        return '""'
    if re.search(r"[:#\[\]{}&*!|>'\"%@`,\n]", value) or value.strip() != value:
        return json.dumps(value, ensure_ascii=False)
    return value


def _render_policy(
    *,
    subject: str,
    kind: str,
    capabilities: list[str],
    findings: list[Finding],
) -> str:
    """Render a deny-by-default policy.yaml.

    Deterministic for a given input so that two scans of the same document
    produce byte-identical policy files (the digest can be quoted in an audit).
    """
    lines: list[str] = []
    lines.append("# Generated by AgentProof.cloud scanner")
    lines.append(f"# source-kind: {kind}")
    lines.append(f"# subject: {_yaml_scalar(subject)}")
    lines.append("# policy: deny by default — no rule match means DENY")
    lines.append("version: 1")
    lines.append(f"subject: {_yaml_scalar(subject)}")
    lines.append("mode: enforce")
    lines.append("")
    lines.append("capabilities:")
    if capabilities:
        for capability in capabilities:
            lines.append(f"  - name: {_yaml_scalar(capability)}")
    else:
        lines.append("  - name: tool.read")
    lines.append("")
    lines.append("rules:")

    # allow explicit safe reads only when nothing critical was found
    critical = sum(1 for f in findings if f.severity == "critical")
    if critical == 0:
        lines.append("  - id: allow-readonly-tools")
        lines.append("    action: \"*\"")
        lines.append("    effect: allow")
        lines.append("    reason: Read-only tool surface, no critical findings")
        lines.append("    conditions:")
        lines.append("      max_input_bytes: 65536")
        lines.append("      required_scopes: [\"read\"]")
        lines.append("      read_only: true")
    else:
        lines.append("  - id: allow-readonly-tools")
        lines.append("    action: \"tool.read.*\"")
        lines.append("    effect: allow")
        lines.append("    reason: Only explicitly read-only tools are pre-approved")
        lines.append("    conditions:")
        lines.append("      max_input_bytes: 32768")

    # deny rules from findings
    seen_actions: set[str] = set()
    for finding in findings:
        action = _action_from_rule(finding.suggested_rule)
        if not action or action in seen_actions:
            continue
        seen_actions.add(action)
        lines.append(f"  - id: deny-{action.replace('*', 'x').replace('.', '-').replace('_', '-')}")
        lines.append(f"    action: {_yaml_scalar(action)}")
        lines.append("    effect: deny")
        lines.append(f"    reason: {_yaml_scalar(finding.title)}")
    lines.append("")
    lines.append("  - id: deny-default")
    lines.append("    action: \"*\"")
    lines.append("    effect: deny")
    lines.append("    reason: Default deny — no matching allow rule")
    lines.append("")
    lines.append("audit:")
    lines.append("  ledger: hash-chain+ed25519")
    lines.append("  sign_before_action: true")
    lines.append("  seal_interval: 100")
    lines.append("  require_receipt: true")
    lines.append("")
    return "\n".join(lines)


def _action_from_rule(rule: str) -> str:
    match = re.search(r"(?:deny|allow):\s*([A-Za-z0-9_.*]+)", rule or "")
    return match.group(1) if match else ""


def scan(kind: str, content: str, *, subject: str = "scanned-agent") -> ScanResult:
    """Entry point used by the API. ``kind`` is ``mcp`` or ``python``."""
    if len(content.encode("utf-8", errors="ignore")) > MAX_CONTENT_BYTES:
        raise ScanInputError(
            f"输入超过 {MAX_CONTENT_BYTES // 1000} KB 上限。请只提交相关的 mcp.json 或工具代码片段。"
        )
    if kind in {"mcp", "mcp.json", "mcp_config"}:
        return scan_mcp(content, subject=subject)
    if kind in {"python", "py", "python_code"}:
        return scan_python(content, subject=subject)
    raise ScanInputError("kind 必须是 mcp 或 python。")


if __name__ == "__main__":  # pragma: no cover - manual usage
    import sys

    data = sys.stdin.read()
    result = scan(sys.argv[1] if len(sys.argv) > 1 else "mcp", data)
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))


# Public aliases: `scan_document` is the canonical entry point used by the
# FastAPI service, the audit tools and the library.
scan_document = scan
scan_mcp_document = scan_mcp
scan_python_document = scan_python

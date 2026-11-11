# AgentProof Cloud (v0.2.0) 商业化上线、收款与战略并购实操手册

本仓库已完成从“本地工具 (v0.1.0)”向**“可收款、可公网部署、可对接大厂并购生态的企业级 SaaS 系统 (v0.2.0)”**的完整代码升级（共 **227 项自动化测试 100% 通过**）。

---

## 一、 新增的 4 大商业变现核心能力清单

| 模块 | 代码路径 | CLI 命令 / 接口 | 商业与并购作用 |
| :--- | :--- | :--- | :--- |
| **1. 病毒式免费获客漏斗 (Shadow MCP & 裸奔工具扫描器)** | `src/agentproof/scanner/` | `agentproof scan <dir> --init-policy policy.yaml` | 复刻 Pluto Security 获客模式：10 秒扫出企业代码库中的高危 MCP 配置与未受控 Python 工具，一键生成防护策略。 |
| **2. 1行代码运行时防越权闸机** | `src/agentproof/runtime/gate.py` | `@gate.guard("db.write")` | 在函数真正运行前 1 毫秒执行策略核验、本地 Ed25519 签名，越权直接抛 `PolicyDeniedError` 阻断，并自动同步云端双签。 |
| **3. 多租户公证云 + Stripe/LemonSqueezy 收款闭环** | `src/agentproof/cloud/` | `agentproof cloud-serve` & `POST /api/v1/webhooks/billing` | 提供独立第三方时间戳双签（Witness Counter-Sign）、三级配额控制（Free / Pro $99 / Enterprise $1,500）及真实 HMAC 支付回调。 |
| **4. 潜在并购方（Vanta / Drata / Datadog）官方导出连接器** | `src/agentproof/exporters/` | `agentproof export chain.json --target vanta\|drata\|datadog` | 将 AI 密码学证据包直接转化为 Vanta、Drata、Datadog 的标准合规报文，打入潜在收购方的企业客户生态。 |

---

## 二、 30 分钟公网部署与收款配置步骤

### 第 1 步：发布开源获客包到 PyPI 与 GitHub（建立开发者分发入口）
1. 在 GitHub 创建公开仓库 `agentproof/agentproof`，将本目录推送上去：
   ```bash
   git init
   git add .
   git commit -m "feat: release AgentProof Cloud v0.2.0 with MCP scanner, RuntimeGate, and Vanta/Datadog exporters"
   git tag v0.2.0
   git push origin main --tags
   ```
2. 本仓库已内置 `.github/workflows/ci-and-publish.yml`，推送 `v0.2.0` 标签后会自动运行 227 项测试并打包发布到 PyPI，全球开发者即可通过 `pip install agentproof` 安装。

### 第 2 步：一键部署 `AgentProof Cloud` 公网 SaaS 平台
本仓库根目录已配置好 `Dockerfile`、`railway.json` 和 `render.yaml`：
1. 登录 [Railway.app](https://railway.app) 或 [Render.com](https://render.com)，点击 **New Project -> Deploy from GitHub repo**，选择本仓库。
2. 平台会自动识别 `Dockerfile` 并挂载持久化存储卷 `/data/agentproof-cloud.db`，启动 `agentproof cloud-serve`。
3. 绑定你的自定义域名（如 `cloud.agentproof.dev`）。

### 第 3 步：开通全球美元信用卡/支付宝自动收款（无需海外公司主体）
1. 注册 [LemonSqueezy](https://www.lemonsqueezy.com)（支持中国大陆身份证 + 国内银行卡/支付宝/PayPal 提现，由平台代缴海外税务）或 Stripe。
2. 创建两个订阅商品：
   - **AgentProof Pro**：`$99 / month`（复制商品结算链接填入环境变量 `AGENTPROOF_CHECKOUT_PRO_URL`）
   - **AgentProof Enterprise & AIUC-1**：`$1,500 / month`（复制结算链接填入环境变量 `AGENTPROOF_CHECKOUT_ENTERPRISE_URL`）
3. 在 LemonSqueezy / Stripe 后台添加 Webhook：
   - **Webhook URL**：`https://你的域名/api/v1/webhooks/billing`
   - **Webhook Signing Secret**：填入环境变量 `AGENTPROOF_WEBHOOK_SECRET`
4. 配置完成后，客户在你的 SaaS 网页点击升级并完成付款，系统会自动通过 HMAC-SHA256 验签并为其开通对应配额，实时计入平台 ARR！

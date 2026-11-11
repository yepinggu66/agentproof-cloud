# AgentProof.cloud — 公开发布清单（2026-11-12）

## 1. 公域网址与代码地址

| 用途 | 地址 |
|---|---|
| **生产官网（全栈，推荐对外）** | https://agentproof-cloud-production.up.railway.app/ |
| 审计服务页（PayPal 直付） | https://agentproof-cloud-production.up.railway.app/#/pricing |
| 免费扫描入口 | https://agentproof-cloud-production.up.railway.app/#/home |
| GitHub Pages 静态镜像 | https://yepinggu66.github.io/agentproof-cloud/ |
| **GitHub 仓库** | https://github.com/yepinggu66/agentproof-cloud |
| v0.2.0 代码快照 | https://github.com/yepinggu66/agentproof-cloud/tree/v0.2.0 |
| 收款链接（PayPal.Me） | https://www.paypal.me/pinggu80 |
| 客服邮箱 | yongping163@qq.com |
| Railway 控制台（私密，勿公开） | https://railway.com/project/2face716-ec30-4b30-986f-73d82c91dc74 |

> 对外统一用**生产官网**；GitHub Pages 只是无后端的静态镜像，不要当主链接发。

## 2. 视频文件

| 文件 | 规格 | 适用平台 |
|---|---|---|
| `dist/promo/agentproof-promo-16x9.mp4` | 1920×1080 · 35s · H.264 + AAC | X/Twitter、Facebook、YouTube、LinkedIn |
| `dist/promo/agentproof-promo-9x16.mp4` | 1080×1920 · 25s · H.264 + AAC | 视频号、抖音、小红书、Reels/Shorts |
| `dist/promo/cover-16x9.png` | 1920×1080 封面 | YouTube 缩略图、X 首图 |
| `dist/promo/cover-9x16.png` | 1080×1920 封面 | 视频号/抖音/小红书封面 |

视频内容：标题卡 → 先签名后执行 → 免费扫描 F 级 + policy.yaml → 双签账本 verify PASS → $490 审计 + PayPal → 四家生态导出 → 官网/GitHub 收尾。画面全部来自真实运行中的产品，无假客户、无假 ARR。

> 音乐：当前是生成的极简环境音。抖音/视频号/小红书建议在平台曲库里换热门音乐（平台已授权）；YouTube 用 YouTube Audio Library；X/Facebook 可保留原声或配免版权音乐。

## 3. 各平台发布文案

### X / Twitter（英文，≤280 字符）

```
Your agent's audit trail is a self-report, not evidence.

AgentProof gates actions before they run, signs each decision twice (Ed25519), hash-chains it, and lets anyone verify offline — no account, no network.

Free scanner for mcp.json / Python tools:
https://agentproof-cloud-production.up.railway.app

Code: https://github.com/yepinggu66/agentproof-cloud
```

### Facebook（英文，稍长）

```
An agent saying "I checked the policy" is a claim. A signed receipt issued before the action is evidence.

AgentProof.cloud gates AI agent actions before they execute, dual-signs every decision with Ed25519, appends it to a SHA-256 hash chain, and lets a third party verify offline with only the public key.

Try the free scanner (mcp.json / Python tool code → A–F grade + deny-by-default policy.yaml):
https://agentproof-cloud-production.up.railway.app

Open source, MIT, 275 tests: https://github.com/yepinggu66/agentproof-cloud

Note: checkout is a sandbox; audit service is paid via PayPal. Exports are mapping drafts, not certified integrations.
```

### YouTube（标题 + 描述）

**标题**：`Agent 的自我汇报不是证据 — 给 AI Agent 的动作签一份可离线验证的证据`

**描述**：
```
Agent 说“我已经查过了、我已经批准了”时，你拿到的是一份声称，不是证据。

AgentProof.cloud 在动作执行前做策略判定，签发平台+租户双 Ed25519 签名回执，写入 SHA-256 哈希链；任何人拿公钥就能离线 verify。

本视频演示：
0:00 问题：自我汇报不是证据
0:05 先签名，后执行
0:15 免费扫描 mcp.json / Python 工具面 → F 级 + 自动生成 policy.yaml
0:25 双签账本与 verify PASS
0:30 审计服务（$490 起，PayPal 直付）
0:35 Vanta / Drata / Datadog / Lloyd's AIUC-1 导出

官网：https://agentproof-cloud-production.up.railway.app
代码：https://github.com/yepinggu66/agentproof-cloud

边界：签名证明签发与完整性，不证明决策正确；导出为映射草案，非厂商认证；自助结账为沙箱。
```

### 视频号（中文）

```
Agent 的自我汇报，不等于证据。

我们在动作执行前就签发平台+租户双签回执，写进哈希链；审计方拿公钥就能离线验证，不需要登录任何后台。

免费扫描 mcp.json 或 Python 工具代码，30 秒出 F 级报告和默认拒绝策略。
官网：agentproof-cloud-production.up.railway.app
代码：github.com/yepinggu66/agentproof-cloud
```

### 抖音（中文，短 hook）

```
你的 Agent 说“我检查过了”，然后呢？

先签名，后执行。双 Ed25519 签名 + 哈希链，任何人可离线验证。
免费扫 mcp.json / Python 工具，30 秒出风险评级。

#AI安全 #AIAgent #MCP #开源项目 #独立开发
```

### 小红书（标题 + 正文）

**标题**：`给 AI Agent 的动作签一份“可验证证据”，而不是让它自己汇报`

**正文**：
```
做 AI Agent 的人都会遇到一个问题：审计要证据，但 agent 的日志本质上是它自己的汇报。

我们的做法是：动作执行前先过策略门，签发平台+租户双签回执，写进哈希链；任何人拿公钥离线 verify。篡改、删除、重排都会 FAIL。

做了个免费扫描器：粘贴 mcp.json 或 Python 工具代码，30 秒出 A–F 评级 + 一份默认拒绝的 policy.yaml。

官网：agentproof-cloud-production.up.railway.app
代码：github.com/yepinggu66/agentproof-cloud

#AI安全 #AIAgent #MCP #独立开发 #开源 #合规
```

## 4. 发布前检查

- [ ] 用生产官网链接（不是 GitHub Pages 镜像）
- [ ] 复制文案时去掉代码块反引号（平台不渲染 Markdown）
- [ ] 16:9 发 X/Facebook/YouTube；9:16 发视频号/抖音/小红书
- [ ] 抖音/视频号/小红书在平台曲库换音乐；YouTube 用 Audio Library
- [ ] 首条评论补充 GitHub 仓库链接（部分平台正文限链）
- [ ] 评论区置顶边界说明：签名证明签发与完整性，不证明决策正确；导出为映射草案；结账为沙箱
- [ ] 不要声称“已获客户/ARR/认证”——目前真实数据是 0 客户、$0 ARR

## 5. 一句话简介（bio / 置顶）

> Vendor-neutral compliance evidence for AI agents. 先签名，后执行。离线可验证。

# AgentProof.cloud — Launch Copy

**Status: pre-publish draft — NO-GO for full launch.** A full-stack instance is live at https://agentproof-cloud-production.up.railway.app/ (site + API + SQLite volume; signup, dual-signed ledger, verify and exports verified). Remaining blockers: checkout is a sandbox, the UI is Chinese-only, and screenshots still contain test data. Publish only when every item in §8 is green.

**Product in one line:** vendor-neutral compliance evidence for AI agents.

**Thesis:** “An agent's own account of what it did is a claim, not evidence.”

**Copy rules used here:** no customer logos, ARR, testimonials, press coverage, benchmark numbers, certifications, or guarantee language. Signatures prove issuance and integrity — not that a decision was correct, and not that a record was never fabricated by the key holder. All pricing and product claims below come from the verified facts; the test ARR visible in the screenshots is called out as test data.

**Formatting:** backticks mark exact strings. Strip them when pasting into HN, Product Hunt, or X, which do not render Markdown.

**If payments go live before publication:** remove the sandbox sentences from the Show HN body, the Product Hunt first comment, the pricing gallery caption, and the first LinkedIn post, then replace them with the real checkout status. Also remove the “no customers / no ARR” lines from §2 and §3 if either exists by publication. Do not leave stale status language.

---

## 1. Positioning

### One-sentence positioning

**AgentProof.cloud is vendor-neutral compliance evidence for AI agents: a deny-by-default gate decides before an action runs, the decision is dual-signed and hash-chained, and anyone can verify it offline with a public key.**

### Three proof points

1. **The decision happens before the action.** The policy gate evaluates the tool call before side effects. There is no default-allow path: only an explicit allow rule with all preconditions met passes, and an evaluation error is a HALT, not a pass.
2. **The record is dual-signed and append-only.** Each decision is signed with two Ed25519 keys — platform and tenant (the customer workspace) — over the same canonical body, then appended to a SHA-256 hash chain. A seal commits to the chain tail. Editing a field, deleting a record, or reordering the chain breaks verification; a full rewrite by the key holder is what the out-of-band seal is for.
3. **Verification does not require us.** A public key and the chain file are enough for a normal check; the published seal is the extra check for a full-chain rewrite. No account, no network, no vendor dashboard. The auditor recomputes; the artifact either verifies or it does not.

### Who this is for

- AI startups whose agents take consequential actions: refunds, file writes, ticket changes, deployments, customer-data access.
- Teams using MCP or Python tool calling that need a concrete artifact for a security review, not another policy PDF.
- Security and compliance engineers who want to verify evidence themselves, including in air-gapped or no-vendor-access environments.
- Teams willing to self-host the MIT core or use a private deployment for stronger operational control.
- Founders who would rather show an auditor a verifier than a screenshot of a dashboard.

### Who this is not for

- Teams looking for a certified GRC platform or a legal opinion. The Vanta / Drata / Datadog / Lloyd's AIUC-1 outputs are mapping drafts, not certified integrations.
- Teams that only need after-the-fact logs or APM. Keep Datadog; this is complementary, not a replacement.
- Teams that cannot make the gate the only path to the side effect. If an agent can bypass the gate, the evidence is incomplete by definition.
- Buyers who require a large vendor, a 24/7 SLA, or a multi-region managed service today. This is a single-maintainer MIT project.
- Anyone who wants a guarantee that an audit or regulatory review will pass. This produces evidence; it does not produce the conclusion.

### Say this / not this

| Say | Do not say |
|---|---|
| signed before the action | tamper-proof |
| tamper-evident | trustless |
| offline-verifiable | proves compliance |
| mapping draft | certified integration |
| evidence, not legal advice | guaranteed audit pass |
| sandbox checkout | live billing (until it is) |

### Internal guardrail: key custody

Dual signing is an integrity control, not separation of trust by itself. In the current build, the tenant private key is encrypted at rest under the service's master key; the service operator can access both keys. A previously published out-of-band seal — retained by someone outside the service — is what catches a full-chain rewrite. Without an external copy, a key holder can rewrite and re-seal the chain, and signatures alone will not catch it. Self-hosting removes the AgentProof operator from the trust path, but it does not turn two keys into two independent organizations. **Do not claim “the vendor cannot forge a record.”** Say what the signatures prove, publish the seal out of band, and let the verifier do the rest.

（中文注：对外只卖“可离线复算的证据”，不卖“绝对可信”。双签是完整性控制；当前托管版的租户私钥由服务端加密保管，别写“厂商无法伪造”。）

---

## 2. Show HN draft

**Title (77/80 characters):**

`Show HN: AgentProof - signed, offline-verifiable audit evidence for AI agents`

**Body (5 paragraphs):**

I built AgentProof.cloud around a simple observation: an agent's own account of what it did is a claim, not evidence. AgentProof sits in front of the tool call: a deny-by-default policy gate decides before the action runs, and the decision is signed before any side effect.

Each decision gets two Ed25519 signatures over the same canonical body — platform key and tenant key — then goes into a SHA-256 hash chain. A seal commits to the chain tail. Verification takes a public key and the chain file; no account, no network, no vendor. Edit a field, delete a record, or reorder the chain without the keys, and the chain no longer verifies.

There is a free scanner on the home page at `https://agentproof-cloud-production.up.railway.app/` (the "免费扫描" section). Paste an `mcp.json` or Python tool code and it runs static rules — MCP config checks and Python code checks, not an LLM and not a mock — to produce an A–F grade, per-finding evidence, and a deny-by-default `policy.yaml`. It does not execute the code; don't paste live secrets.

Limits, because they matter: signatures prove issuance and integrity, not that a decision was correct, and not that whoever holds the keys never fabricated a record. Publish the seal out of band for that. Exports to Vanta, Drata, Datadog, and Lloyd's AIUC-1 are mapping drafts, not certified integrations. The hosted checkout is a sandbox: it creates a tenant and API key, but takes no money.

The core is MIT and self-hostable. I'm the only maintainer; there are no customers, ARR, or benchmark numbers to cite. I'd like feedback from people running agents with real side effects: where would this fit in your stack, and what would make the evidence unusable to your auditor? Code: `https://github.com/yepinggu66/agentproof-cloud`.

### Anticipated critical comments — and honest answers

**1. “A signature only proves you signed it. It can't prove the decision was right — or that you didn't just sign a false record.”**

Correct. The signature proves the record was issued by those keys and has not changed; it does not prove the decision was correct. The decision comes from the policy gate before the call, not from the agent's narrative. If the policy is wrong, you get a verifiable record of a wrong decision — useful, but not the same thing. And if the key holder rewrites and re-signs the whole chain, only a previously published out-of-band seal, retained outside the service, catches it; without that external copy, signatures alone will not. That is why the seal is part of the mechanism, not an optional extra.

**2. “Why not just Datadog? We already have logs.”**

Keep Datadog. Logs are after-the-fact telemetry, and many agent logs are just the agent's own report. This is a pre-action gate plus a portable artifact that a third party can verify without your observability account. The Datadog export is a mapping draft for alerting; it is complementary, not a replacement.

**3. “The agent can just bypass the gate. Then what?”**

Then you have no evidence, and that is the honest limit. AgentProof only covers actions that actually pass through the gate. Deployment has to make the gate the only path to the side effect, and monitor for direct calls. If an agent can issue the refund or write the file without passing the gate, the absence of a record is not proof that nothing happened. Better to say that up front than sell a guarantee the architecture cannot make.

（中文注：HN 标题 77 字符，正文 5 段；三个质疑都正面回答，不回避“签名不等于正确”和“绕过 gate 就没有证据”。）

---

## 3. Product Hunt draft

**Tagline (56/60 characters):**

`Signed, offline-verifiable evidence for AI agent actions`

**Short description (237/260 characters):**

`AgentProof.cloud gates AI agent actions before they run, signs each decision twice with Ed25519, hash-chains it, and lets anyone verify offline. Scan an mcp.json or Python tool for a free A–F risk grade and a deny-by-default policy.yaml.`

**Pricing snapshot (must match the live page):**

- **Free — $0:** 100 signed decisions/month.
- **Pro — $99/month:** 5,000/month, Vanta / Drata / Datadog export drafts.
- **Enterprise — $1,500/month:** 100,000/month, Lloyd's AIUC-1 underwriting pack, private deployment.

All exports are mapping drafts, not certified integrations.

**First comment (founder note — post immediately after launch):**

Hi, I'm [FOUNDER_NAME], the maintainer of AgentProof.cloud.

I built it because an agent audit trail that starts with the agent's own account is a claim, not evidence: it says it checked the policy, and the log repeats the claim.

The mechanism: a deny-by-default policy gate evaluates the tool call before side effects. The decision is signed with the platform key and the tenant key over the same canonical body, appended to a SHA-256 hash chain, and sealed at the tail. Verification needs the public key and the chain file — no account, no network.

What's real today: the scanner is static analysis for MCP configs and Python tool code, with an A–F grade, per-finding evidence, and a generated `policy.yaml`. The gate, ledger, dual signatures, chain verification, and mapping-draft exports are implemented. The core is MIT and self-hostable.

What's not: signatures prove issuance and integrity, not that a decision was correct, and not that a key holder never fabricated a record. Publish the seal out of band. Exports are mapping drafts, not certified integrations. Billing isn't wired yet — checkout creates a tenant and API key but takes no money. Key custody matters too: the current build holds the tenant key encrypted at rest under the service master key, so dual signing is an integrity control, not a separation-of-trust setup.

No customers, ARR, or press coverage yet. It's a public beta from one maintainer. If you run agents that issue refunds, write files, or touch production, I'd like your hardest question — I'll answer it here.

### Gallery captions (5 screenshots)

**1. Scanner** (`scanner.png`) — Paste an `mcp.json` or Python tool. Real static rules return an A–F grade, per-finding evidence, and a deny-by-default `policy.yaml`. No signup.

**2. Console** (`console-verified.png`) — Every ALLOW/DENY is signed before the action and appended to the chain. Recompute the hashes and both signatures in the console; PASS/FAIL is the product.

**3. Pricing** (`pricing.png`) — Free: 100 signed decisions/month. Pro: 5,000 plus export drafts. Enterprise: 100,000, Lloyd's AIUC-1 pack, private deployment. Checkout is sandboxed during beta — it issues a key, not a charge.

**4. Integrations** (`integrations.png`) — The same chain exported as Vanta / Drata / Datadog / Lloyd's AIUC-1 mapping drafts. Drafts, not certified integrations — the disclaimer travels in the payload.

**5. Home** (`home.png`) — The thesis: an agent's own account is a claim, not evidence. The gate signs before the side effect, so the record exists before the outcome.

**Before uploading these:** the current captures show a test tenant (“Acme Support”) and a test ARR ($1,188), and the pricing shot contains “14-day trial” and “99.9% SLA” language that is not in the verified fact set. Recapture on a clean tenant and remove or verify those claims. Do not present test data as traction. The current UI is also Chinese; see §8 for the English-surface gate.

（中文注：首评先讲边界，再讲功能；沙箱和“无客户/无 ARR”必须写明。现有截图有测试 ARR 和未核实 SLA，不能直接上。）

---

## 4. Cold email to an AI-startup CTO

### Subject lines (3 options)

1. `Your agent's audit trail is a self-report`
2. `Free scan of [COMPANY]'s agent/MCP repo`
3. `Before the next refund: signed agent evidence`

### Personalization inputs

- `[FIRST_NAME]` — the recipient, not “team”.
- `[COMPANY]` — company name.
- `[SPECIFIC_DETAIL]` — a real public repo, docs page, launch post, or job listing. Do not fake this.
- `[SURFACE]` — where you saw it: repo, docs page, launch post, or job listing.
- `[ONE_LINE_ABOUT_THEIR_AGENT]` — describe the action the agent takes, not the company's funding.
- `[REPO/PATH]` — a public repo or a path the recipient explicitly shares.

### Body (94/150 words)

Hi [FIRST_NAME],

I saw [SPECIFIC_DETAIL] in [COMPANY]'s [SURFACE] — [ONE_LINE_ABOUT_THEIR_AGENT]. That's the kind of surface where an auditor eventually asks what the agent did, not what it reported.

AgentProof.cloud gates agent actions before they run: deny by default, two Ed25519 signatures, a SHA-256 chain, and offline verification with a public key.

Free offer: send one public [REPO/PATH] or mcp.json and I'll return an A–F grade, per-finding evidence, and a deny-by-default policy.yaml. No account, no call.

If useful, reply with the link. If not, reply "no" and I'll close the loop.

[NAME]
[ROLE], AgentProof.cloud
https://agentproof-cloud-production.up.railway.app/

**Safety:** only scan public code or a file they explicitly share. Never ask for keys, `.env` files, customer data, or private repository access.

（中文注：只承诺一次免费扫描，不承诺“包过审计/包合作”；CTA 是回链接，不是约电话。）

---

## 5. Chinese version — cold DM (WeChat / LinkedIn)

**≤120 字（116 字，含标点）：**

你好[姓名]，看到[公司]的 agent 在做[动作]。发我公开的 mcp.json 或仓库，我免费回你 A–F 评级、逐条证据和默认拒绝策略，无需注册。AgentProof 提供动作前的双签证据，不替代日志。不合适回“不用”即可。

**English gloss (for internal review only):**

Hi [NAME], I saw [COMPANY]'s agent doing [ACTION]. I can run a free scan on a public mcp.json or repo and send back an A–F grade, per-finding evidence, and a deny-by-default policy — no signup. AgentProof provides dual-signed evidence before an action runs; it does not replace logs. If this isn't relevant, reply “no” and I won't follow up.

（中文注：不写“保证合规”，只给证据；不附链接、不催回复，降低打扰感。）

---

## 6. LinkedIn / X posts

### LinkedIn — post 1 (launch)

An agent audit trail that starts with the agent's own account is a claim, not evidence. It says it checked the policy, and the log repeats the claim.

AgentProof.cloud changes the order. A deny-by-default gate decides before the action runs. The decision is signed with the platform and tenant Ed25519 keys, appended to a SHA-256 chain, and sealed. Anyone with the public key can verify offline — no account, no network.

The free scanner takes an `mcp.json` or Python tool and returns an A–F grade, per-finding evidence, and a deny-by-default `policy.yaml`. Real static rules, not a demo.

Boundaries: signatures prove issuance and integrity, not that the decision was right, and not that a key holder never fabricated a record. Publish the seal out of band. Exports are mapping drafts, not certified integrations. Hosted checkout is a sandbox today.

MIT core, one maintainer. I'm looking for teams whose agents issue refunds, write files, or touch production. What would your auditor need to see?

### LinkedIn — post 2 (technical boundary)

A good test for any agent audit tool: can your auditor verify a record without logging into your vendor's dashboard?

If not, you have a screenshot, not evidence.

AgentProof's chain verifies with a public key and a file, offline. That doesn't prove the decision was correct. It proves the record wasn't edited, deleted, or reordered without detection.

That distinction is the product. Not a dashboard.

### X — post 1 (launch)

Your agent's audit log may be a self-report. AgentProof gates the action before it runs: deny by default, two Ed25519 signatures, SHA-256 chain. Verify offline with a public key — no account, no network. Free scanner: mcp.json or Python tool → A–F grade + policy.yaml.

### X — post 2 (boundary)

Signatures prove a record was issued and has not changed. They do not prove the decision was right, or that the key holder never fabricated it. We say that in the docs and on the site. Publish the seal out of band to catch a full rewrite. Evidence, not claims.

（中文注：X 两条都在 280 字符内；没有 hashtag 堆砌，也没有增长数据。）

---

## 7. Objection handling

1. **“We already have logging.”** Logs tell you what the agent reported after the fact; AgentProof decides and signs before the side effect, then gives you a chain an auditor can verify offline.

2. **“We don't use MCP.”** MCP is one input to the free scanner, not the evidence model; the decision point is the tool-call boundary, and Python tool code is scanned too.

3. **“Will this slow us down?”** It adds a policy evaluation and two signatures before the call; measure it in your path, and note that a signing failure is a denial, not a fail-open.

4. **“Is it legally binding?”** No — it is evidence, not a legal opinion or certification; your auditor or insurer decides whether it satisfies a specific requirement.

5. **“Is this just another dashboard?”** The dashboard is a viewer; the deliverable is a signed chain plus an offline verifier, and you can ignore the UI entirely.

6. **“Why trust a one-person project?”** You shouldn't have to — the core is MIT, so self-host it or verify the output with the public key offline; the evidence should not depend on trusting the maintainer.

**Precondition, not an objection:** if an action can run without passing the gate, it is outside the evidence. Make the gate the only path to the side effect, and monitor for bypass.

（中文注：六个反对意见都用一句话回答；最后补一句“绕过 gate 就没有证据”，避免把边界藏起来。）

---

## 8. Pre-publish checklist (go / no-go)

**Recommended launch mode until Stripe or LemonSqueezy is wired:** lead with the free scanner and the MIT self-host path. Present Pro and Enterprise as “planned” or “join the waitlist”, not as a checkout. If you keep the sandbox, say “sandbox — creates a tenant and API key, takes no money” on the first pricing screen, not in the FAQ.

**Current status: NO-GO for full launch.** The full stack is live on Railway; remaining blockers: sandbox checkout, test data in screenshots, and a Chinese-only product surface for an English-language launch.

Treat each line as a gate: a single NO-GO blocks publication.

1. **Public URL is live and un-gated.** `https://agentproof-cloud-production.up.railway.app/` resolves over HTTPS from a clean browser and a phone, with no password wall, basic-auth prompt, or “coming soon” page. **Go only if** this works without a session cookie. **Current: PASS** — verified HTTP 200 on the site and `/api/health`, the scanner calls the real `/api/scan`, and a tenant signup → ledger → verify → export run passed.

2. **The live build is the real build.** The site is in LIVE mode, the scanner calls the real `/api/scan`, and the console is not a localStorage demo passed off as production. If the static/offline demo is reachable, it is labelled “offline demo” on the page, not only in the footer. **Current: PASS on the Railway instance** (the GitHub Pages mirror remains the labelled offline demo).

3. **Checkout tells the truth.** Every checkout surface says “sandbox — creates a tenant and API key, takes no money” until payments are live, and the CTA does not say “confirm payment” while no money moves. **Go only if** the wording matches the actual `checkout.mode`. **Current: NO-GO** — checkout is a sandbox.

4. **No fake proof anywhere.** Zero customer logos, testimonials, “trusted by” strips, press mentions, invented ARR, invented scan counts, invented decision counts, or benchmark numbers. The production instance is reset to ARR $0 / 0 tenants; the console and pricing screenshots still show a test tenant and $1,188 ARR — recapture before publishing. The header ARR must be $0 or hidden unless it is computed from real paid tenants.

5. **Pricing is internally consistent.** $0 / 100 signed decisions per month; $99 / 5,000; $1,500 / 100,000. Remove or verify any “14-day trial”, “99.9% SLA”, “BYOK”, annual discount, “unlimited”, or other claim not in the verified fact set. **Current: fixed in the site copy** — “14-day trial” and “99.9% SLA” were removed and the pricing screenshot was recaptured; re-verify the live page at launch.

6. **Export disclaimers are visible.** The integrations page says “mapping draft, not a certified integration”, and each payload carries the same disclaimer. The Vanta / Drata / Datadog / Lloyd's AIUC-1 names are not used to imply certification or partnership.

7. **Claim audit is clean.** Search the site, decks, and posts for “tamper-proof”, “trustless”, “certified”, “compliant”, “guaranteed”, “bank-grade”, and superlatives. Replace with “tamper-evident”, “offline-verifiable”, “mapping draft”, “evidence, not legal advice”. No “EU AI Act compliant” or “SOC 2 certified” language unless a real audit exists.

8. **Key custody and boundaries are stated.** “Dual-signed” is not presented as “the vendor cannot forge a record”. The copy explains that signatures do not prove correctness or non-fabrication, that the seal must be published out of band, and that the gate only covers actions that pass through it.

9. **`hello@agentproof.cloud` is ready.** The mailbox exists, is monitored, and can receive from an external address. Send and receive a test; check spam placement. Set SPF, DKIM, and DMARC for the domain. If a security contact is listed, it must also be monitored.

10. **Legal and privacy pages exist.** Privacy policy, terms, acceptable use, data retention, and a DPA path for EU customers. State who operates the service and how to contact them. The evidence product is not legal advice; say so.

11. **Scanner data handling is documented.** Confirm that pasted code is not written to application logs, that rate limiting is active, and that error messages do not echo secrets. Tell users not to paste live credentials. If the claim is “analysed in memory only”, verify it in the running deployment.

12. **Secrets and demo data are clean.** No keys in the public repo, screenshots, or browser bundles. Rotate anything exposed during demos. `data/` is not publicly served. HTTPS and HSTS are on. Run a dependency and secret scan before launch.

13. **Offline verification is tested independently.** On a clean machine with only the public key and a chain file, verify a good chain and a deliberately tampered one. Confirm the tampered file fails. Document where the public key and the out-of-band seal are published, and how a third party obtains them.

14. **English product surface is ready.** The overseas launch needs an English UI or an English-primary bilingual UI. The current site is `lang="zh-CN"` and the screenshots are Chinese; do not publish English launch copy over Chinese screenshots and call it ready. Recapture the five gallery images at the platform's required size with no test data.

15. **All placeholders are replaced and tested.** `https://agentproof-cloud-production.up.railway.app/`, `https://github.com/yepinggu66/agentproof-cloud`, `[FOUNDER_NAME]`, `[EMAIL]`, `[COMPANY]`, `[FIRST_NAME]`, `[NAME]`, `[ROLE]`, `[SPECIFIC_DETAIL]`, `[SURFACE]`, `[ONE_LINE_ABOUT_THEIR_AGENT]`, and `[REPO/PATH]` are filled. Click every link from a logged-out browser.

16. **Support and incident paths exist.** A monitored inbox, a status page or health endpoint, and a one-line incident response plan. Do not advertise a 99.9% SLA unless there is a real service commitment behind it.

17. **Two-reader claim review is done.** The maintainer plus one outside technical reader check every public claim against this document and the code. If a claim cannot be demonstrated in the product, delete it. Freeze the copy after this review.

18. **Launch-day monitoring is staffed.** Watch the support inbox, scanner rate limits, API errors, checkout errors, and social mentions. Have a rollback path for the site and a written answer ready for “can I verify this myself?”.

19. **If you are charging: payments are actually live.** Stripe or LemonSqueezy checkout completes with a test card and a real card, webhooks are idempotent, receipts and refunds work, tax handling is configured, and cancellation is self-serve. If any of this is false, launch in free-scanner/waitlist mode instead.

**Sign-off rule:** two people (maintainer + outside reader) must mark every line GO. If any line is NO-GO, do not publish. Re-run this list after any pricing, claim, or screenshot change.

（中文注：上线前最关键的四项：公开 URL 可访问、沙箱字样可见、截图无假 ARR/未核实 SLA、英文界面可用。任一不满足就不要发。）

---

*Prepared as launch copy only; not legal advice. All product boundaries above are intentional and should survive editing.*

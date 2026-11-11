# AgentProof Cloud — Complete Go-To-Market & Acquisition Launch Kit

Everything below is ready to copy, paste, and execute to drive PyPI installs, Pro ($99/mo) & Enterprise ($1,500/mo) ARR, and strategic M&A visibility.

Live Site: https://neon-sawine-352869.netlify.app

---

## 1. Hacker News (`Show HN`) Launch Post

- **Title**: `Show HN: AgentProof – Pre-execution Ed25519 receipts & Shadow MCP scanner for AI agents`
- **Text / First Comment**:
  > An audit log written by an AI agent after the fact is a claim, not evidence.
  >
  > After OpenAI acquired Promptfoo and Cisco acquired Galileo, enterprise compliance teams and insurers started asking for a vendor-neutral layer that enforces fail-closed policy gates *before* an agent executes a tool call and signs immutable hash-chained receipts.
  >
  > What AgentProof (MIT, Python) ships today:
  > 1. `agentproof scan . --init-policy policy.yaml`: AST + config scanner that finds unpinned `npx -y` MCP servers, plaintext env secrets, and unguarded shell/SQL tools, then synthesizes a fail-closed YAML policy.
  > 2. `@gate.guard("wire.transfer")`: 1-line Python gate that evaluates policy and signs an Ed25519 receipt *before* the underlying function executes.
  > 3. `agentproof evidence` & `export --target vanta|drata|datadog`: Maps chains to EU AI Act Art. 26, ISO 42001, SOC 2 CC6/CC7, and Lloyd's AIUC-1 insurability scorecards.
  >
  > Try the zero-install browser scanner here: https://neon-sawine-352869.netlify.app
  > Feedback on the receipt schema and fail-closed defaults is very welcome.

---

## 2. Product Hunt Launch Copy

- **Tagline**: `Pre-execution Ed25519 receipts & Shadow MCP scanner for AI agents`
- **Description**:
  `AgentProof prevents rogue AI tool calls before they run. Scan your repo for Shadow MCP servers in 10 seconds, wrap tools with a 1-line fail-closed policy gate, and export tamper-evident EU AI Act Art. 26, SOC 2, and AIUC-1 compliance packs to Vanta, Drata, and Datadog.`

---

## 3. Automated Outbound Lead Discovery Command

Run the built-in growth scout on public GitHub repositories or local checkouts to generate personalized audit reports, starter `policy.yaml` patches, and outreach emails:

```bash
# Scan public GitHub repos exposing mcpServers
export GITHUB_TOKEN=ghp_your_token
agentproof scout --github-query "filename:mcp.json mcpServers" --limit 25 --out-dir leads/

# Or scan a folder of cloned AI repos offline
agentproof scout --dir ./cloned-ai-repos --out-dir leads/
```

This creates:
- `leads/pipeline.csv` sorted from highest `risk_score` (CRITICAL/HIGH first)
- `leads/<repo>/audit-report.md`, `policy.yaml`, and `outreach.md`

---

## 4. Micro-PE / Strategic M&A Data Room Checklist (Target $500K–$30M Exit)

Keep these 4 live metrics updated from `/api/v1/health`:
1. **Verified ARR & Paying Orgs**: Target 50–100 teams on Pro ($99/mo = $60K–$120K ARR) for Acquire.com cash exit, or $300K+ ARR + GRC integrations for Strategic M&A.
2. **Ecosystem Attachment**: Track % of paying tenants using `agentproof export --target vanta|drata|datadog` (primary acquisition signal for Vanta, Drata, Datadog, CrowdStrike).
3. **OSS Funnel Velocity**: Weekly `pip install agentproof` downloads + `agentproof scan` runs.
4. **100% Clean IP**: Runtime dependencies strictly limited to `PyYAML`, `cryptography`, and `click` (all permissive licenses, zero AGPL/NC contamination).

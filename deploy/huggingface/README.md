---
title: AgentProof Cloud
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Signed, offline-verifiable audit evidence for AI agents
---

# AgentProof Cloud (Hugging Face Spaces preview)

Commercial site + SaaS API for vendor-neutral AI agent compliance evidence.

- Paste an `mcp.json` or Python tool code → A–F risk grade + generated deny-by-default `policy.yaml`
- Self-serve tenant onboarding (sandbox checkout — no charge is taken)
- Dual-signed (Ed25519) append-only ledger with offline verification
- Vanta / Drata / Datadog / Lloyd's AIUC-1 export drafts

This Space is a **demo/preview**: its storage is ephemeral (SQLite lives on the
container filesystem), so tenants and ledgers reset when the Space restarts.
Signatures prove issuance and integrity, not that a decision was correct; the
exports are mapping drafts, not certified integrations. Checkout is a sandbox.

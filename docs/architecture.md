# Architecture

Status: v0.2.0 merged (2026-11-11). This document is the due-diligence map: what
each layer does, where the trust boundaries are, and what is still missing.

## Layers

```
  agent action
      │
      ▼
┌──────────────────┐   deny-by-default policy evaluation
│ runtime gate      │   (src/agentproof/runtime/gate.py)
│ @gate.guard(...)  │────────── HALT / DENY ──▶ no side effect
└────────┬─────────┘
         │ ALLOW: sign receipt BEFORE the call
         ▼
┌──────────────────┐   Ed25519 (platform + tenant), canonical JSON, SHA-256
│ receipt + chain   │   (core/receipt.py, core/chain.py, core/canonical.py)
└────────┬─────────┘
         │ append-only, prev_hash linked
         ▼
┌──────────────────┐   SQLite storage, seal, WORM-style semantics
│ cloud notary      │   (cloud/storage.py, cloud/notary.py)
│ + billing         │   (cloud/billing.py — Stripe/LemonSqueezy HMAC webhooks)
└────────┬─────────┘
         │ verify with public key only (core/verify.py)
         ▼
┌──────────────────┐
│ evidence exports  │   Article 26 pack, AIBOM, Vanta/Drata/Datadog/AIUC-1
│ (exporters/)      │   (evidence/, exporters/integrations.py, insurability)
└──────────────────┘
```

## Two entry points

| Entry point | For | Code |
|---|---|---|
| `agentproof` CLI / Python API | developers embedding the gate or generating evidence offline | `src/agentproof/` |
| AgentProof.cloud web service | self-serve scanning, tenant onboarding, console, exports | `server/` + `site/` |

The commercial service intentionally calls its own scanner (`server/scan.py`)
and shares only the cryptographic primitives through `server/signing.py` and
`server/ledger.py`. The library keeps an independent scanner
(`src/agentproof/scanner/`). **Consolidating the two scanners is deliberate
follow-up work** — the browser port in `site/assets/scanner.js` is already kept
byte-identical to `server/scan.py` by `tests/test_scanner_parity.py`.

## Trust model

- Each record body is canonical JSON (sorted keys, no whitespace), hashed with
  SHA-256, chained by `prev_hash`, and signed twice: platform key + tenant key.
- The seal commits to the chain tail; it only detects a full rewrite if a copy
  was published out of band first.
- Verification needs the public key and the chain file. No account, no network.
- Signatures prove issuance and integrity, not that a decision was correct, and
  not that a key holder never fabricated a record. The product says this
  everywhere, including in every export payload.

## Deployment topology

| Artifact | What it serves | Where |
|---|---|---|
| `site/` (static) | marketing site, browser scanner, offline demo console | GitHub Pages (live), Netlify |
| `server/app.py` (FastAPI + SQLite) | real API: scan, tenants, signed ledger, exports | Docker / Railway / any host |
| `netlify/functions/api.mts` | stateless preview endpoints only; refuses to issue tenants or ARR | Netlify |

## What exists vs what is missing

**Exists and tested (272 tests):**
- core chain / receipt / policy / canonical JSON / verification
- runtime gate, cloud notary, storage, billing webhook verification
- MCP + Python scanner (two implementations + browser port, parity-tested)
- commercial API: tenants, quotas, dual-signed ledger, exports, audit reports
- signed audit report generator (`tools/audit_report.py`)

**Missing, in priority order:**
1. **Payments**: checkout is a sandbox; needs Stripe/LemonSqueezy account + KYC.
2. **Public backend**: the API runs locally only; needs a host/account.
3. **CI**: `.github/workflows` cannot be pushed with the current token (needs
   `workflow` scope); the v0.2.0 workflow is archived at
   `deploy/v0.2.0/ci-and-publish.yml`.
4. **Scanner consolidation** (see above) and a single release version story.
5. **Multi-tenant storage at scale**: SQLite single-process is fine for demos,
   not for a paid multi-tenant service.
6. **Brand, customers, case studies**: an acquirer buys traction and a team as
   much as code; the services-first plan is how those get created.

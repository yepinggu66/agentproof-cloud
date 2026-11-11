# v0.2.0 archive

This folder preserves the original v0.2.0 assets that were merged into the
repository on 2026-11-11:

- `site/index.html` — the earlier single-file marketing site (Tailwind CDN,
  client-side demo console). **Not deployed**: it hardcodes a $19,188 ARR and
  fabricates tenants/receipts in the browser. Kept for reference only; the live
  site is `site/` at the repository root.
- `README.md` — the v0.1.0 / v0.2.0 library README.
- `COMMERCIAL_LAUNCH_GUIDE.md`, `LAUNCH_KIT.md` — launch notes from that phase.
  Some claims in them (public URL, live revenue) were never true; see
  `docs/commercial-plan.md` and `docs/launch-copy.md` for the current, honest
  versions.

The real, tested software foundation from v0.2.0 now lives at `src/agentproof/`
(runtime gate, cloud notary, storage/billing, exporters, scanner) and its tests
were merged into `tests/`.

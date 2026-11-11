import type { Config, Context } from "@netlify/functions"

// Stateless Netlify preview API for the AgentProof.cloud static site.
//
// IMPORTANT — this function has no database attached. It must never invent
// tenants, API keys or revenue: a key that authenticates nothing is worse than
// no key, and hardcoded ARR on a compliance vendor's site is indefensible.
// Real tenant creation, Ed25519 dual-signed receipts and ARR live in the
// Docker service (server/app.py + server/ledger.py). This endpoint only powers
// the browser scanner preview and reports the truth: no backend is connected.

export default async (req: Request, context: Context) => {
  const url = new URL(req.url)
  const path = url.pathname

  if (req.method === "GET" && path === "/api/v1/health") {
    return Response.json({
      status: "ok",
      service: "agentproof-cloud-netlify",
      mode: "static-preview",
      backend_connected: false,
      region: context.server?.region ?? "local",
      metrics: {
        total_tenants: 0,
        paid_tenants: 0,
        mrr_usd: 0,
        arr_usd: 0,
      },
      note: "No database is attached to this serverless preview. Real tenants, signed receipts and ARR require the Docker API (see server/).",
    })
  }

  if (req.method === "POST" && path === "/api/v1/scan-snippet") {
    const body = (await req.json().catch(() => ({}))) as Record<string, unknown>
    const content = String(body.content ?? "")
    const findings: Array<Record<string, string>> = []

    if (content.includes("npx") && content.includes("-y")) {
      findings.push({
        rule_id: "MCP-001",
        severity: "HIGH",
        title: "Unpinned auto-install MCP server (npx -y)",
      })
    }
    if (
      content.includes("shell") ||
      content.includes("subprocess") ||
      content.includes("os.system")
    ) {
      findings.push({
        rule_id: "MCP-002",
        severity: "CRITICAL",
        title: "Unrestricted shell/process execution exposed to agent",
      })
    }
    if (content.includes('"/"') || content.includes("C:\\")) {
      findings.push({
        rule_id: "MCP-003",
        severity: "CRITICAL",
        title: "Root filesystem mounted into MCP server",
      })
    }
    if (
      content.toUpperCase().includes("DELETE FROM") ||
      content.toUpperCase().includes("DROP TABLE")
    ) {
      findings.push({
        rule_id: "TOOL-004",
        severity: "HIGH",
        title: "Unguarded destructive SQL mutation in agent tool",
      })
    }

    const riskScore = Math.min(100, findings.length * 25)
    return Response.json({
      preview: true,
      disclaimer: "Lite preview rules only. The full scanner is in site/assets/scanner.js and server/scan.py.",
      report: {
        risk_score: riskScore,
        security_grade: riskScore === 0 ? "A" : riskScore <= 25 ? "C" : "F",
        findings,
      },
    })
  }

  if (req.method === "POST" && path === "/api/v1/tenants") {
    return Response.json(
      {
        error: "backend_not_connected",
        message:
          "This static preview cannot create tenants or API keys. Run the Docker service (server/app.py) for real self-serve onboarding.",
      },
      { status: 503 }
    )
  }

  return Response.json({ error: `Route not found: ${path}` }, { status: 404 })
}

export const config: Config = {
  path: "/api/v1/*",
}

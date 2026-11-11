# AI Bill of Materials — acme-support-agent

- Generated: 2026-10-26T17:42:24Z
- Source trace: `trace.jsonl`
- Assets: 1 agent(s), 2 tool(s), 1 model(s)
- Errors observed: 1

## Agents

| Agent | Events | Tools used |
|---|---|---|
| support-agent | 6 | `kb.search`, `db.write` |

## Tools

| Tool | Calls | Called by |
|---|---|---|
| `db.write` | 1 | support-agent |
| `kb.search` | 1 | support-agent |

## Models

| Model | Calls | Used by |
|---|---|---|
| `unknown` | 1 | support-agent |

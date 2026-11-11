"""AI Bill of Materials.

The single largest compliance gap in the 2026 data is the boring one: most
organizations cannot list the AI systems they run. One survey found 83% have
no formal inventory; another found 40% of sampled enterprise AI systems could
not be classified under the AI Act's risk tiers at all.

You cannot classify what you have not inventoried. So the inventory comes
first, and it is the cheapest possible compliance control: a machine-readable
list of every agent, model, MCP server, and skill, with what each one may do.

The AIBOM is derived from a recorded trace, so it reflects what actually ran
rather than what someone remembers deploying.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..capture.events import AgentEvent, EventKind
from ..core.canonical import digest_bytes

__all__ = ["Aibom", "build_aibom", "render_aibom_markdown"]


@dataclass
class Aibom:
    """A machine-readable inventory of observed AI assets."""

    subject: str = ""
    generated_at: str = ""
    source_trace: str = ""
    agents: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    models: list[dict[str, Any]] = field(default_factory=list)
    errors: int = 0
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "agentproof-aibom-v1",
            "subject": self.subject,
            "generated_at": self.generated_at,
            "source_trace": self.source_trace,
            "agents": self.agents,
            "tools": self.tools,
            "models": self.models,
            "summary": self.summary,
        }

    def save_json(self, path: str | Path) -> Path:
        import json

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        return out

    def save_markdown(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_aibom_markdown(self), encoding="utf-8")
        return out


def build_aibom(
    events: list[AgentEvent],
    *,
    subject: str = "",
    source_trace: str = "",
) -> Aibom:
    """Build an AI Bill of Materials from a recorded trace."""
    agents: dict[str, dict[str, Any]] = {}
    tools: dict[str, dict[str, Any]] = {}
    models: dict[str, dict[str, Any]] = {}
    errors = 0

    for event in events:
        if event.kind is EventKind.ERROR:
            errors += 1

        agent_name = event.agent or "unknown"
        agent_entry = agents.setdefault(
            agent_name,
            {"name": agent_name, "event_count": 0, "actions": [], "tools": []},
        )
        agent_entry["event_count"] += 1

        if event.kind is EventKind.TOOL_CALL and event.action:
            tool_entry = tools.setdefault(
                event.action,
                {
                    "name": event.action,
                    "call_count": 0,
                    "agents": [],
                    "input_digests": [],
                    "sample_inputs": None,
                },
            )
            tool_entry["call_count"] += 1
            if agent_name not in tool_entry["agents"]:
                tool_entry["agents"].append(agent_name)
            if len(tool_entry["input_digests"]) < 20:
                tool_entry["input_digests"].append(digest_bytes(event.inputs))
            if tool_entry["sample_inputs"] is None:
                tool_entry["sample_inputs"] = event.inputs
            if event.action not in agent_entry["tools"]:
                agent_entry["tools"].append(event.action)
            if event.action not in agent_entry["actions"]:
                agent_entry["actions"].append(event.action)

        if event.kind is EventKind.LLM_CALL:
            model_name = str(
                event.payload.get("model") or event.payload.get("model_name") or "unknown"
            )
            models.setdefault(
                model_name,
                {"name": model_name, "call_count": 0, "agents": []},
            )["call_count"] += 1
            if agent_name not in models[model_name]["agents"]:
                models[model_name]["agents"].append(agent_name)

    return Aibom(
        subject=subject,
        generated_at=_dt.datetime.now(_dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        source_trace=source_trace,
        agents=sorted(agents.values(), key=lambda a: a["name"]),
        tools=sorted(tools.values(), key=lambda t: t["name"]),
        models=sorted(models.values(), key=lambda m: m["name"]),
        errors=errors,
        summary={
            "agent_count": len(agents),
            "tool_count": len(tools),
            "model_count": len(models),
            "total_events": len(events),
            "error_events": errors,
        },
    )


def _md_cell(value: Any) -> str:
    """Escape a value for a Markdown table cell (``|`` would split the row)."""
    return str(value).replace("|", "\\|")


def render_aibom_markdown(aibom: Aibom) -> str:
    """Render the AIBOM as Markdown."""
    lines: list[str] = []
    lines.append(f"# AI Bill of Materials — {aibom.subject or 'unnamed subject'}")
    lines.append("")
    lines.append(f"- Generated: {aibom.generated_at}")
    if aibom.source_trace:
        lines.append(f"- Source trace: `{aibom.source_trace}`")
    lines.append(
        f"- Assets: {aibom.summary.get('agent_count', 0)} agent(s), "
        f"{aibom.summary.get('tool_count', 0)} tool(s), "
        f"{aibom.summary.get('model_count', 0)} model(s)"
    )
    lines.append(f"- Errors observed: {aibom.summary.get('error_events', 0)}")
    lines.append("")

    lines.append("## Agents")
    lines.append("")
    lines.append("| Agent | Events | Tools used |")
    lines.append("|---|---|---|")
    for agent in aibom.agents:
        tools = ", ".join(f"`{_md_cell(t)}`" for t in agent["tools"]) or "—"
        lines.append(
            f"| {_md_cell(agent['name'])} | {agent['event_count']} | {tools} |"
        )
    lines.append("")

    lines.append("## Tools")
    lines.append("")
    lines.append("| Tool | Calls | Called by |")
    lines.append("|---|---|---|")
    for tool in aibom.tools:
        agents = ", ".join(_md_cell(a) for a in tool["agents"]) or "—"
        lines.append(
            f"| `{_md_cell(tool['name'])}` | {tool['call_count']} | {agents} |"
        )
    lines.append("")

    if aibom.models:
        lines.append("## Models")
        lines.append("")
        lines.append("| Model | Calls | Used by |")
        lines.append("|---|---|---|")
        for model in aibom.models:
            agents = ", ".join(_md_cell(a) for a in model["agents"]) or "—"
            lines.append(
                f"| `{_md_cell(model['name'])}` | {model['call_count']} | "
                f"{agents} |"
            )
        lines.append("")

    return "\n".join(lines)

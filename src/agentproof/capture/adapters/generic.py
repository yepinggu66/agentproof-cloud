"""Generic adapter — the fallback for frameworks we have not special-cased.

This is also the reference implementation for anyone writing their own
adapter. It accepts a loosely-specified dict and maps recognizable fields
onto the neutral model.

Recognized input shape::

    {
      "type": "tool_call",       # or "llm_call", "agent_start", ...
      "ts": "2026-10-27T00:00:00Z",   # optional
      "name": "kb.search",       # the action
      "input": {...},            # or "inputs" / "arguments" / "args"
      "output": {...},           # optional
      "error": "...",            # optional
      "agent": "support-agent",  # optional
      "tags": ["regression-target"],
      "extra": {...}             # anything else, kept in payload
    }
"""

from __future__ import annotations

from typing import Any

from ...core.canonical import digest_bytes
from ..events import AgentEvent, EventKind
from .base import AdapterError

__all__ = ["GenericAdapter"]

_TYPE_MAP = {
    "agent_start": EventKind.AGENT_START,
    "agent_end": EventKind.AGENT_END,
    "agent.finish": EventKind.AGENT_END,
    "llm_call": EventKind.LLM_CALL,
    "model_call": EventKind.LLM_CALL,
    "tool_call": EventKind.TOOL_CALL,
    "tool_result": EventKind.TOOL_RESULT,
    "error": EventKind.ERROR,
    "note": EventKind.NOTE,
}


class GenericAdapter:
    """Best-effort translation of a loosely-specified event dict."""

    name = "generic"

    def translate(self, event: dict[str, Any]) -> list[AgentEvent]:
        if not isinstance(event, dict):
            raise AdapterError(f"expected a mapping, got {type(event).__name__}")

        raw_type = str(event.get("type") or event.get("kind") or "").lower()
        kind = _TYPE_MAP.get(raw_type)
        if kind is None:
            # Unknown event types are preserved as notes rather than dropped.
            # Losing information silently is worse than carrying a generic tag.
            kind = EventKind.NOTE

        inputs = (
            event.get("input")
            or event.get("inputs")
            or event.get("arguments")
            or event.get("args")
            or {}
        )
        outputs = (
            event.get("output")
            or event.get("outputs")
            or event.get("result")
            or {}
        )
        if not isinstance(inputs, dict):
            inputs = {"value": inputs}
        if not isinstance(outputs, dict):
            outputs = {"value": outputs}

        known = {
            "type",
            "kind",
            "ts",
            "timestamp",
            "name",
            "action",
            "input",
            "inputs",
            "arguments",
            "args",
            "output",
            "outputs",
            "result",
            "error",
            "agent",
            "tags",
        }
        extra = {k: v for k, v in event.items() if k not in known}

        ts = str(event.get("ts") or event.get("timestamp") or AgentEvent.now_ts())

        payload: dict[str, Any] = dict(extra)
        if kind is EventKind.NOTE and "text" not in payload:
            payload["text"] = str(event.get("text") or "")

        return [
            AgentEvent(
                kind=kind,
                ts=ts,
                agent=str(event.get("agent") or ""),
                action=str(event.get("name") or event.get("action") or ""),
                inputs=inputs,
                outputs=outputs,
                error=event.get("error"),
                payload=payload,
                tags=[str(t) for t in (event.get("tags") or [])],
            )
        ]

    @staticmethod
    def inputs_digest(inputs: dict[str, Any]) -> str:
        """Stable digest of an input payload, used by the chain."""
        return digest_bytes(inputs)

"""OpenAI Agents SDK adapter.

Translates the OpenAI Agents SDK's run-item shapes into the neutral model.

The SDK emits "run items" as it works:

* ``RunItemStarted`` / ``RunItemCompleted`` wrapping a tool call item
* tool items carry ``name``, ``arguments`` (a JSON string) and ``output``
* agent starts / ends arrive as their own items

Like the LangGraph adapter, this one does not import the SDK. It reads the
documented attribute names and degrades gracefully if they change.

Wiring it up::

    from agentproof.capture.adapters.openai_agents import OpenAIAgentsAdapter
    from agentproof.capture import Recorder

    recorder = Recorder("trace.jsonl")
    adapter = OpenAIAgentsAdapter()
    for item in result.new_items:
        recorder.record_many(adapter.translate(item))
"""

from __future__ import annotations

import json
from typing import Any

from ..events import AgentEvent, EventKind
from .base import AdapterError

__all__ = ["OpenAIAgentsAdapter"]


class OpenAIAgentsAdapter:
    """Translate OpenAI Agents SDK run items into neutral events."""

    name = "openai-agents"

    def translate(self, event: Any) -> list[AgentEvent]:
        if event is None:
            return []

        # Already a plain dict: hand it to the generic shape reader.
        if isinstance(event, dict):
            return self._translate_dict(event)

        # A pydantic model or similar object: project it to a dict first.
        # The SDK's run items are pydantic models, so this is the common case,
        # not an edge case.
        projected = _project(event)
        if projected is not None:
            return self._translate_dict(projected)

        type_name = type(event).__name__
        ts = AgentEvent.now_ts()

        if type_name == "MessageOutputItem":
            raw = getattr(event, "raw_item", None)
            role = getattr(raw, "role", None)
            return [
                AgentEvent(
                    kind=EventKind.LLM_CALL,
                    ts=ts,
                    agent="openai-agents",
                    outputs={"content": _safe(getattr(raw, "content", None))},
                    payload={"role": role},
                )
            ]

        if type_name == "ToolCallItem":
            return [
                AgentEvent(
                    kind=EventKind.TOOL_CALL,
                    ts=ts,
                    agent="openai-agents",
                    action=str(getattr(event, "name", "") or ""),
                    inputs=_parse_arguments(getattr(event, "arguments", None)),
                    payload={
                        "call_id": getattr(event, "call_id", None),
                        "raw_item": _safe(getattr(event, "raw_item", None)),
                    },
                )
            ]

        if type_name == "ToolCallOutputItem":
            return [
                AgentEvent(
                    kind=EventKind.TOOL_RESULT,
                    ts=ts,
                    agent="openai-agents",
                    action=str(getattr(event, "name", "") or ""),
                    outputs={"output": _safe(getattr(event, "output", None))},
                    payload={"call_id": getattr(event, "call_id", None)},
                )
            ]

        if type_name == "RunItemStarted" or type_name == "RunItemCompleted":
            inner = getattr(event, "name", None)
            payload_item = getattr(event, "payload", None)
            if payload_item is not None:
                return self.translate(payload_item)
            return [
                AgentEvent(
                    kind=EventKind.NOTE,
                    ts=ts,
                    agent="openai-agents",
                    payload={"wrapper": type_name, "inner": str(inner)},
                )
            ]

        if type_name == "MessageOutputItem":  # pragma: no cover - unreachable
            return []

        return [
            AgentEvent(
                kind=EventKind.NOTE,
                ts=ts,
                agent="openai-agents",
                payload={"unhandled_type": type_name},
            )
        ]

    # ------------------------------------------------------------------
    def _translate_dict(self, event: dict[str, Any]) -> list[AgentEvent]:
        raw_type = str(event.get("type") or event.get("kind") or "").lower()
        ts = str(event.get("ts") or AgentEvent.now_ts())

        # A projected SDK item often lacks an explicit "type" but does carry
        # the fields that identify it. Infer rather than discard.
        if not raw_type:
            if "arguments" in event and ("name" in event or "tool" in event):
                raw_type = "tool_call"
            elif "output" in event and "name" in event:
                raw_type = "tool_call_output"
            elif "content" in event:
                raw_type = "message"

        if raw_type in ("tool_call", "tool_call_item"):
            return [
                AgentEvent(
                    kind=EventKind.TOOL_CALL,
                    ts=ts,
                    agent="openai-agents",
                    action=str(event.get("name") or event.get("tool_name") or ""),
                    inputs=_parse_arguments(
                        event.get("arguments", event.get("input"))
                    ),
                    payload={"call_id": event.get("call_id")},
                )
            ]

        if raw_type in ("tool_call_output", "tool_call_output_item"):
            return [
                AgentEvent(
                    kind=EventKind.TOOL_RESULT,
                    ts=ts,
                    agent="openai-agents",
                    action=str(event.get("name") or event.get("tool_name") or ""),
                    outputs={"output": event.get("output")},
                    payload={"call_id": event.get("call_id")},
                )
            ]

        if raw_type in ("message", "message_output_item"):
            return [
                AgentEvent(
                    kind=EventKind.LLM_CALL,
                    ts=ts,
                    agent="openai-agents",
                    outputs={"content": event.get("content")},
                    payload={"role": event.get("role")},
                )
            ]

        return [
            AgentEvent(
                kind=EventKind.NOTE,
                ts=ts,
                agent="openai-agents",
                payload={"unhandled": event},
            )
        ]


def _project(value: Any) -> dict[str, Any] | None:
    """Project a pydantic-style object onto a plain dict, or return ``None``.

    The OpenAI Agents SDK hands out pydantic models, so supporting them is
    the normal case. A projection that fails is not an error: the caller
    falls back to the attribute-based reader.
    """
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump(mode="json")
        except Exception:  # noqa: BLE001
            try:
                dumped = model_dump()
            except Exception:  # noqa: BLE001
                return None
        if isinstance(dumped, dict):
            return dumped

    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        try:
            dumped = dict_method()
        except Exception:  # noqa: BLE001
            return None
        if isinstance(dumped, dict):
            return dumped

    return None


def _parse_arguments(raw: Any) -> dict[str, Any]:
    """The SDK hands back a JSON string; tolerate a dict too."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return {"_raw": raw}
        return dict(parsed) if isinstance(parsed, dict) else {"value": parsed}
    return {"value": _safe(raw)}


#: Guard rails for :func:`_safe`; identical to the LangGraph adapter's so both
#: adapters degrade the same way. A self-referential or pathologically nested
#: payload becomes a readable placeholder instead of a ``RecursionError``.
_SAFE_MAX_DEPTH = 64
_SAFE_CIRCULAR = "<circular>"
_SAFE_DEPTH_PLACEHOLDER = "<max-depth>"


def _safe(value: Any) -> Any:
    """Best-effort JSON-able projection of an arbitrary object.

    Never raises for a cyclic or over-deep structure: those become
    ``"<circular>"`` / ``"<max-depth>"`` strings. Only the *current* ancestry
    is tracked, so a value that merely appears twice (a DAG, not a cycle) is
    still rendered in full both times.
    """
    return _safe_walk(value, set(), 0)


def _safe_walk(value: Any, seen: set[int], depth: int) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if depth >= _SAFE_MAX_DEPTH:
        return _SAFE_DEPTH_PLACEHOLDER

    marker = id(value)
    if marker in seen:
        return _SAFE_CIRCULAR
    seen.add(marker)
    try:
        if isinstance(value, dict):
            return {
                str(k): _safe_walk(v, seen, depth + 1) for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [_safe_walk(v, seen, depth + 1) for v in value]
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            try:
                return _safe_walk(model_dump(mode="json"), seen, depth + 1)
            except Exception:  # noqa: BLE001
                pass
        dict_method = getattr(value, "dict", None)
        if callable(dict_method):
            try:
                return _safe_walk(dict_method(), seen, depth + 1)
            except Exception:  # noqa: BLE001
                pass
        return repr(value)
    finally:
        seen.discard(marker)

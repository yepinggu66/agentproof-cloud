"""LangGraph adapter.

Translates LangGraph's stream-mode event shapes into the neutral model.

LangGraph emits dictionaries keyed by node name when streaming. The shapes we
care about:

* ``{"__start__": {...}}``            → agent start
* ``{"<node>": {"messages": [...]}}``  → llm call (one per message)
* ``{"<node>": {"tools": [...]}}``     → tool call
* tool ``ToolMessage`` with ``status == "error"`` → error event

This adapter deliberately reads *documented, stable* fields only. It does not
import LangGraph, so the package installs and tests without it. If LangGraph
renames a field, this adapter keeps working on the older field and the new
one is simply not captured — a degradation, never a crash.

Wiring it up::

    from agentproof.capture.adapters.langgraph import LangGraphAdapter
    from agentproof.capture import Recorder

    recorder = Recorder("trace.jsonl")
    adapter = LangGraphAdapter()
    for chunk in graph.stream(inputs, stream_mode="values"):
        recorder.record_many(adapter.translate(chunk))
"""

from __future__ import annotations

from typing import Any

from ..events import AgentEvent, EventKind
from .base import AdapterError

__all__ = ["LangGraphAdapter"]


class LangGraphAdapter:
    """Translate LangGraph stream chunks into neutral events."""

    name = "langgraph"

    def translate(self, event: dict[str, Any]) -> list[AgentEvent]:
        if not isinstance(event, dict):
            raise AdapterError(f"expected a mapping, got {type(event).__name__}")

        events: list[AgentEvent] = []
        # agent start marker
        if "__start__" in event:
            events.append(
                AgentEvent(
                    kind=EventKind.AGENT_START,
                    ts=AgentEvent.now_ts(),
                    agent="langgraph",
                    payload={"inputs": event["__start__"]},
                )
            )
            return events

        for node_name, node_payload in event.items():
            if node_name == "__end__":
                events.append(
                    AgentEvent(
                        kind=EventKind.AGENT_END,
                        ts=AgentEvent.now_ts(),
                        agent="langgraph",
                        payload={"outputs": node_payload},
                    )
                )
                continue

            if not isinstance(node_payload, dict):
                events.append(
                    AgentEvent(
                        kind=EventKind.NOTE,
                        ts=AgentEvent.now_ts(),
                        agent="langgraph",
                        payload={"node": node_name, "value": node_payload},
                    )
                )
                continue

            events.extend(self._translate_node(node_name, node_payload))

        return events

    # ------------------------------------------------------------------
    def _translate_node(
        self, node_name: str, payload: dict[str, Any]
    ) -> list[AgentEvent]:
        events: list[AgentEvent] = []
        ts = AgentEvent.now_ts()

        for message in payload.get("messages") or []:
            events.extend(self._translate_message(node_name, message, ts))

        for tool_call in payload.get("tools") or []:
            events.append(
                AgentEvent(
                    kind=EventKind.TOOL_CALL,
                    ts=ts,
                    agent="langgraph",
                    action=self._tool_name(tool_call),
                    inputs=self._tool_inputs(tool_call),
                    payload={"node": node_name, "raw": _safe(tool_call)},
                )
            )

        return events

    def _translate_message(
        self, node_name: str, message: Any, ts: str
    ) -> list[AgentEvent]:
        if not isinstance(message, dict):
            # LangChain messages are pydantic models. Project them so the
            # same field-reading code works for both.
            projected = _project(message)
            if projected is not None:
                return self._translate_message(node_name, projected, ts)

            # A message that is neither a mapping nor projectable is
            # unexpected but must not be dropped: losing it silently means
            # the trace no longer reflects what ran.
            return [
                AgentEvent(
                    kind=EventKind.NOTE,
                    ts=ts,
                    agent="langgraph",
                    payload={"node": node_name, "unparsed_message": _safe(message)},
                )
            ]

        msg_type = str(message.get("type") or message.get("role") or "").lower()
        content = message.get("content")

        # LangChain's AIMessage carries tool calls in `tool_calls`, a list of
        # {"name": ..., "args": {...}} dicts. A single AIMessage may carry
        # *several* parallel tool calls; every one of them is a real action
        # that the policy layer must see, so collect them all. Stopping at the
        # first one would silently hide actions such as a DENY-level
        # ``db.write`` from the trace and from every regression assertion
        # built on it.
        events: list[AgentEvent] = []
        for tool_call in message.get("tool_calls") or []:
            events.append(
                AgentEvent(
                    kind=EventKind.TOOL_CALL,
                    ts=ts,
                    agent="langgraph",
                    action=self._tool_name(tool_call),
                    inputs=self._tool_inputs(tool_call),
                    payload={
                        "node": node_name,
                        "tool_call_id": tool_call.get("id")
                        if isinstance(tool_call, dict)
                        else None,
                    },
                )
            )
        if events:
            return events

        if isinstance(content, list):
            # Anthropic-style content blocks: pull out every tool_use. Like
            # ``tool_calls`` above, these can arrive in parallel.
            tool_events: list[AgentEvent] = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    tool_events.append(
                        AgentEvent(
                            kind=EventKind.TOOL_CALL,
                            ts=ts,
                            agent="langgraph",
                            action=str(block.get("name") or ""),
                            inputs=dict(block.get("input") or {}),
                            payload={
                                "node": node_name,
                                "tool_use_id": block.get("id"),
                            },
                        )
                    )
            if tool_events:
                return tool_events
            # Content blocks that are not tool calls are still worth keeping
            # as a note; dropping them would lose the model's visible output.
            return [
                AgentEvent(
                    kind=EventKind.NOTE,
                    ts=ts,
                    agent="langgraph",
                    outputs={"content": content},
                    payload={"node": node_name, "message_type": msg_type},
                )
            ]

        if msg_type in ("tool", "toolmessage") or "tool_call_id" in message:
            is_error = str(message.get("status") or "").lower() == "error"
            return [
                AgentEvent(
                    kind=EventKind.ERROR if is_error else EventKind.TOOL_RESULT,
                    ts=ts,
                    agent="langgraph",
                    action=str(message.get("name") or ""),
                    outputs={"content": content},
                    error=str(message.get("content")) if is_error else None,
                    payload={
                        "node": node_name,
                        "tool_call_id": message.get("tool_call_id"),
                    },
                )
            ]

        if msg_type in ("ai", "assistant"):
            return [
                AgentEvent(
                    kind=EventKind.LLM_CALL,
                    ts=ts,
                    agent="langgraph",
                    outputs={"content": content},
                    payload={
                        "node": node_name,
                        "model": message.get("response_metadata", {}).get(
                            "model_name"
                        )
                        if isinstance(message.get("response_metadata"), dict)
                        else None,
                    },
                )
            ]

        return [
            AgentEvent(
                kind=EventKind.NOTE,
                ts=ts,
                agent="langgraph",
                outputs={"content": content},
                payload={"node": node_name, "message_type": msg_type},
            )
        ]

    @staticmethod
    def _tool_name(tool_call: Any) -> str:
        if isinstance(tool_call, dict):
            return str(tool_call.get("name") or tool_call.get("tool") or "")
        return str(getattr(tool_call, "name", "") or "")

    @staticmethod
    def _tool_inputs(tool_call: Any) -> dict[str, Any]:
        if isinstance(tool_call, dict):
            args = tool_call.get("args") or tool_call.get("input") or {}
            return dict(args) if isinstance(args, dict) else {"value": args}
        args = getattr(tool_call, "args", None)
        return dict(args) if isinstance(args, dict) else {}


def _project(value: Any) -> dict[str, Any] | None:
    """Project a pydantic-style object onto a plain dict, or return ``None``."""
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


#: Guard rails for :func:`_safe`. A payload can legitimately be deep, but it
#: must never be able to take the process down: a self-referential structure
#: (or a pathologically nested one) degrades to a readable placeholder instead
#: of a ``RecursionError``. "Degrade, never crash" is the contract here.
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

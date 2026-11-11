"""Regression tests for RT-04 and RT-07 (adapter capture completeness).

RT-04: a single LangGraph ``AIMessage`` may carry several *parallel* tool
calls. Every one of them is a real action the policy layer must see — missing
one (especially a DENY-level action such as ``db.write``) means the trace and
the regression assertions built from it silently lie about what the agent did.

RT-07: ``_safe()`` projects arbitrary payloads into JSON-able data. A
self-referential or pathologically nested payload must degrade to a readable
placeholder, never raise ``RecursionError``: both adapters promise "degrade,
never crash".

These tests are additive; they do not touch the existing adapter tests.
"""

from __future__ import annotations

import json

from agentproof.capture import Recorder, read_trace
from agentproof.capture.adapters import LangGraphAdapter, OpenAIAgentsAdapter
from agentproof.capture.adapters.langgraph import _safe as langgraph_safe
from agentproof.capture.adapters.openai_agents import _safe as openai_agents_safe
from agentproof.capture.events import EventKind

CIRCULAR = "<circular>"
MAX_DEPTH = "<max-depth>"


# ----------------------------------------------------------------------
# RT-04 — every parallel tool call reaches the neutral event stream / trace
# ----------------------------------------------------------------------
PARALLEL_TOOL_CALLS = [
    {"name": "kb.search", "args": {"q": "refund policy"}, "id": "c1"},
    {"name": "db.write", "args": {"sql": "DELETE FROM orders"}, "id": "c2"},
    {"name": "order.refund", "args": {"order": "A-1001"}, "id": "c3"},
]


def _ai_message_with_parallel_tool_calls() -> dict:
    return {
        "agent": {
            "messages": [
                {
                    "type": "ai",
                    "content": "",
                    "tool_calls": [dict(call) for call in PARALLEL_TOOL_CALLS],
                }
            ]
        }
    }


def test_parallel_tool_calls_are_all_translated_in_order():
    events = LangGraphAdapter().translate(_ai_message_with_parallel_tool_calls())

    assert len(events) == len(PARALLEL_TOOL_CALLS)
    assert all(event.kind is EventKind.TOOL_CALL for event in events)
    assert [event.action for event in events] == [
        "kb.search",
        "db.write",
        "order.refund",
    ]
    assert [event.inputs for event in events] == [call["args"] for call in PARALLEL_TOOL_CALLS]
    assert [event.payload["tool_call_id"] for event in events] == ["c1", "c2", "c3"]


def test_deny_level_parallel_tool_call_is_visible_in_the_trace(tmp_path):
    """db.write is the action a policy would DENY; it must not vanish."""
    trace = tmp_path / "parallel_trace.jsonl"

    adapter = LangGraphAdapter()
    recorder = Recorder(str(trace))
    try:
        recorder.record_many(adapter.translate(_ai_message_with_parallel_tool_calls()))
    finally:
        recorder.close()

    recorded = read_trace(trace)
    assert [event.action for event in recorded] == [
        "kb.search",
        "db.write",
        "order.refund",
    ]
    assert "db.write" in [event.action for event in recorded]
    assert [event.payload["tool_call_id"] for event in recorded] == ["c1", "c2", "c3"]


def test_single_tool_call_output_is_unchanged():
    """The common one-call case must keep its exact pre-fix event shape."""
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "ai",
                        "content": "",
                        "tool_calls": [
                            {"name": "kb.search", "args": {"q": "refund"}, "id": "c1"}
                        ],
                    }
                ]
            }
        }
    )

    assert len(events) == 1
    fields = events[0].to_dict()
    fields.pop("ts")
    assert fields == {
        "kind": "tool.call",
        "agent": "langgraph",
        "action": "kb.search",
        "inputs": {"q": "refund"},
        "outputs": {},
        "error": None,
        "payload": {"node": "agent", "tool_call_id": "c1"},
        "tags": [],
    }


def test_content_with_multiple_tool_use_blocks_collects_all():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "ai",
                        "content": [
                            {"type": "text", "text": "calling two tools in parallel"},
                            {
                                "type": "tool_use",
                                "id": "tu_1",
                                "name": "kb.search",
                                "input": {"q": "x"},
                            },
                            {
                                "type": "tool_use",
                                "id": "tu_2",
                                "name": "db.write",
                                "input": {"sql": "DELETE"},
                            },
                        ],
                    }
                ]
            }
        }
    )

    assert len(events) == 2
    assert [event.kind for event in events] == [EventKind.TOOL_CALL, EventKind.TOOL_CALL]
    assert [event.action for event in events] == ["kb.search", "db.write"]
    assert [event.inputs for event in events] == [{"q": "x"}, {"sql": "DELETE"}]
    assert [event.payload["tool_use_id"] for event in events] == ["tu_1", "tu_2"]


def test_single_content_tool_use_output_is_unchanged():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "ai",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "tu_1",
                                "name": "kb.search",
                                "input": {"q": "x"},
                            }
                        ],
                    }
                ]
            }
        }
    )

    assert len(events) == 1
    fields = events[0].to_dict()
    fields.pop("ts")
    assert fields == {
        "kind": "tool.call",
        "agent": "langgraph",
        "action": "kb.search",
        "inputs": {"q": "x"},
        "outputs": {},
        "error": None,
        "payload": {"node": "agent", "tool_use_id": "tu_1"},
        "tags": [],
    }


# ----------------------------------------------------------------------
# RT-07 — circular payloads degrade to a readable placeholder
# ----------------------------------------------------------------------
def test_langgraph_safe_circular_dict_degrades():
    payload: dict = {"name": "db.write", "args": {}}
    payload["self"] = payload

    projected = langgraph_safe(payload)

    assert projected["name"] == "db.write"
    assert projected["args"] == {}
    assert projected["self"] == CIRCULAR


def test_langgraph_safe_circular_list_degrades():
    loop: list = []
    loop.append(loop)

    assert langgraph_safe(loop) == [CIRCULAR]


def test_openai_agents_safe_circular_dict_degrades():
    payload: dict = {"name": "kb.search", "args": {}}
    payload["self"] = payload

    projected = openai_agents_safe(payload)

    assert projected["name"] == "kb.search"
    assert projected["self"] == CIRCULAR


def test_safe_placeholders_are_consistent_between_adapters():
    payload: dict = {"name": "x"}
    payload["self"] = payload
    loop: list = []
    loop.append(loop)

    first = langgraph_safe({"obj": payload, "loop": loop})
    second = openai_agents_safe({"obj": payload, "loop": loop})

    assert first == second
    assert first["obj"]["self"] == CIRCULAR
    assert first["loop"] == [CIRCULAR]


def test_shared_acyclic_reference_is_rendered_in_full():
    """A value that appears twice (a DAG) is not a cycle and must not collapse."""
    shared = {"k": 1}

    assert langgraph_safe([shared, shared]) == [{"k": 1}, {"k": 1}]


def test_langgraph_translate_survives_recursive_payload(tmp_path):
    tool: dict = {"name": "db.write", "args": {"table": "orders"}}
    tool["self"] = tool

    events = LangGraphAdapter().translate({"agent": {"tools": [tool]}})

    assert len(events) == 1
    assert events[0].action == "db.write"
    assert events[0].payload["raw"]["self"] == CIRCULAR

    # The sanitized payload must also be JSON-serializable, so the recorder
    # keeps working instead of failing with "Circular reference detected".
    trace = tmp_path / "circular_trace.jsonl"
    recorder = Recorder(str(trace))
    try:
        recorder.record_many(events)
    finally:
        recorder.close()

    recorded = read_trace(trace)
    assert recorded[0].payload["raw"]["self"] == CIRCULAR


def test_openai_agents_translate_survives_recursive_payload(tmp_path):
    class ToolCallItem:
        name = "db.write"
        arguments = '{"table": "orders"}'
        call_id = "c9"

        def __init__(self):
            self.raw_item = {"role": "assistant"}
            self.raw_item["self"] = self.raw_item

    events = OpenAIAgentsAdapter().translate(ToolCallItem())

    assert len(events) == 1
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "db.write"
    assert events[0].inputs == {"table": "orders"}
    assert events[0].payload["raw_item"]["self"] == CIRCULAR

    trace = tmp_path / "openai_circular_trace.jsonl"
    recorder = Recorder(str(trace))
    try:
        recorder.record_many(events)
    finally:
        recorder.close()
    assert read_trace(trace)[0].payload["raw_item"]["self"] == CIRCULAR


def test_safe_object_projecting_to_itself_degrades():
    class SelfRef:
        def model_dump(self, mode=None):
            return {"me": self}

    assert langgraph_safe(SelfRef()) == {"me": CIRCULAR}
    assert openai_agents_safe(SelfRef()) == {"me": CIRCULAR}


def test_safe_projects_legacy_dict_method_objects():
    class Legacy:
        def dict(self):
            return {"a": 1}

    assert langgraph_safe(Legacy()) == {"a": 1}
    assert openai_agents_safe(Legacy()) == {"a": 1}


def test_safe_falls_back_when_model_dump_raises():
    class BrokenDump:
        def model_dump(self, mode=None):
            raise RuntimeError("nope")

        def dict(self):
            return {"b": 2}

    assert langgraph_safe(BrokenDump()) == {"b": 2}
    assert openai_agents_safe(BrokenDump()) == {"b": 2}


def test_safe_opaque_object_degrades_to_repr():
    class Opaque:
        __slots__ = ()

    obj = Opaque()
    projected = langgraph_safe(obj)
    assert isinstance(projected, str)
    assert "Opaque" in projected
    # Both adapters must degrade identically.
    assert openai_agents_safe(obj) == projected


def test_safe_falls_back_to_repr_when_dict_method_raises():
    class BrokenDict:
        def dict(self):
            raise RuntimeError("nope")

    obj = BrokenDict()
    assert "BrokenDict" in langgraph_safe(obj)
    assert "BrokenDict" in openai_agents_safe(obj)


def test_safe_depth_is_bounded_in_both_adapters():
    """A very deep payload is truncated with a readable marker, not a crash."""
    deep: dict = {"leaf": "bottom"}
    for _ in range(500):
        deep = {"child": deep}

    for safe in (langgraph_safe, openai_agents_safe):
        projected = safe(deep)
        json.dumps(projected)  # must stay serializable

        depth = 0
        node = projected
        while isinstance(node, dict) and "child" in node:
            node = node["child"]
            depth += 1

        assert node == MAX_DEPTH
        assert 0 < depth < 500

"""LangChain / LangGraph message shapes.

LangChain's messages are pydantic models, and ``AIMessage`` carries its tool
calls in a ``tool_calls`` list rather than in the content. Both are common
enough in production that the adapter has to handle them properly.
"""

from __future__ import annotations

from agentproof.capture.adapters import LangGraphAdapter
from agentproof.capture.events import EventKind


class FakeAI:
    """Stands in for LangChain's AIMessage."""

    def __init__(self, **fields):
        self._fields = fields

    def model_dump(self, mode=None):
        return dict(self._fields)


def test_tool_calls_field_is_read():
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
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "refund"}
    assert events[0].payload["tool_call_id"] == "c1"


def test_pydantic_message_is_projected():
    message = FakeAI(type="ai", content="thinking", response_metadata={"model_name": "m"})
    events = LangGraphAdapter().translate({"agent": {"messages": [message]}})
    assert events[0].kind is EventKind.LLM_CALL
    assert events[0].payload["model"] == "m"


def test_pydantic_message_with_tool_calls():
    message = FakeAI(
        type="ai",
        content="",
        tool_calls=[{"name": "db.write", "args": {"sql": "DELETE t"}, "id": "c2"}],
    )
    events = LangGraphAdapter().translate({"agent": {"messages": [message]}})
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "db.write"


def test_tool_message_with_tool_call_id():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "tool",
                        "name": "kb.search",
                        "content": "3 hits",
                        "tool_call_id": "c1",
                    }
                ]
            }
        }
    )
    assert events[0].kind is EventKind.TOOL_RESULT
    assert events[0].payload["tool_call_id"] == "c1"


def test_unprojectable_object_becomes_a_note():
    class Opaque:
        __slots__ = ()

    events = LangGraphAdapter().translate({"agent": {"messages": [Opaque()]}})
    assert len(events) == 1
    assert events[0].kind is EventKind.NOTE
    assert "unparsed_message" in events[0].payload

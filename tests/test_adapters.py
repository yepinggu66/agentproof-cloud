"""Adapters must translate framework events without leaking vendor specifics."""

from __future__ import annotations

from agentproof.capture import AgentEvent, EventKind, get_adapter
from agentproof.capture.adapters import (
    AdapterError,
    GenericAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
)


# ----------------------------------------------------------------------
# generic
# ----------------------------------------------------------------------
def test_generic_adapter_maps_tool_call():
    events = GenericAdapter().translate(
        {"type": "tool_call", "name": "kb.search", "input": {"q": "x"}}
    )
    assert len(events) == 1
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "x"}


def test_generic_adapter_accepts_alternative_field_names():
    events = GenericAdapter().translate(
        {"type": "tool_call", "action": "kb.search", "arguments": {"q": "x"}}
    )
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "x"}


def test_generic_adapter_keeps_unknown_events_as_notes():
    events = GenericAdapter().translate({"type": "something_new", "value": 1})
    assert events[0].kind is EventKind.NOTE
    assert events[0].payload["value"] == 1


def test_generic_adapter_rejects_non_mapping():
    import pytest

    with pytest.raises(AdapterError):
        GenericAdapter().translate("not a dict")


# ----------------------------------------------------------------------
# langgraph
# ----------------------------------------------------------------------
def test_langgraph_maps_start_marker():
    events = LangGraphAdapter().translate({"__start__": {"input": "hi"}})
    assert events[0].kind is EventKind.AGENT_START


def test_langgraph_maps_end_marker():
    events = LangGraphAdapter().translate({"__end__": {"output": "done"}})
    assert events[0].kind is EventKind.AGENT_END


def test_langgraph_maps_ai_message_to_llm_call():
    events = LangGraphAdapter().translate(
        {"agent": {"messages": [{"type": "ai", "content": "thinking"}]}}
    )
    assert events[0].kind is EventKind.LLM_CALL


def test_langgraph_maps_tool_use_block():
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
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "x"}


def test_langgraph_maps_tool_message_error():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "tool",
                        "name": "db.write",
                        "content": "permission denied",
                        "status": "error",
                        "tool_call_id": "c1",
                    }
                ]
            }
        }
    )
    assert events[0].kind is EventKind.ERROR
    assert events[0].error == "permission denied"


# ----------------------------------------------------------------------
# openai agents
# ----------------------------------------------------------------------
def test_openai_adapter_parses_json_string_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "kb.search", "arguments": '{"q": "x"}'}
    )
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].inputs == {"q": "x"}


def test_openai_adapter_tolerates_malformed_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "kb.search", "arguments": "not json"}
    )
    assert events[0].inputs == {"_raw": "not json"}


def test_openai_adapter_handles_tool_output_item():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call_output", "name": "kb.search", "output": {"hits": 3}}
    )
    assert events[0].kind is EventKind.TOOL_RESULT
    assert events[0].outputs == {"output": {"hits": 3}}


def test_openai_adapter_handles_unknown_items():
    events = OpenAIAgentsAdapter().translate(object())
    assert events[0].kind is EventKind.NOTE


# ----------------------------------------------------------------------
# registry
# ----------------------------------------------------------------------
def test_registry_resolves_known_adapters():
    assert get_adapter("langgraph").name == "langgraph"
    assert get_adapter("openai-agents").name == "openai-agents"
    assert get_adapter("openai_agents").name == "openai-agents"


def test_registry_falls_back_to_generic():
    assert get_adapter("something-unknown").name == "generic"
    assert get_adapter("").name == "generic"


def test_adapters_do_not_import_their_frameworks():
    """The package must install and run without LangGraph or the OpenAI SDK."""
    import sys

    assert "langgraph" not in sys.modules
    assert "agents" not in sys.modules

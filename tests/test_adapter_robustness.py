"""Adapters meet messy real-world input.

These are the paths where a production trace breaks a parser: a field that
should be a dict is a string, a content block is missing, an SDK version
renames something. The rule everywhere is the same: **degrade, never crash**.
A monitoring tool that crashes on an unusual event is worse than useless,
because it takes the agent down with it.
"""

from __future__ import annotations

import pytest

from agentproof.capture.adapters import (
    AdapterError,
    GenericAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
)
from agentproof.capture.events import EventKind


# ----------------------------------------------------------------------
# generic: malformed input
# ----------------------------------------------------------------------
def test_generic_handles_string_input_value():
    events = GenericAdapter().translate(
        {"type": "tool_call", "name": "x", "input": "plain string"}
    )
    assert events[0].inputs == {"value": "plain string"}


def test_generic_handles_non_dict_output():
    events = GenericAdapter().translate(
        {"type": "tool_result", "name": "x", "output": 42}
    )
    assert events[0].outputs == {"value": 42}


def test_generic_handles_missing_type():
    events = GenericAdapter().translate({"name": "x", "input": {"a": 1}})
    assert events[0].kind is EventKind.NOTE


def test_generic_keeps_unknown_fields_in_payload():
    events = GenericAdapter().translate(
        {"type": "tool_call", "name": "x", "input": {}, "custom": "value"}
    )
    assert events[0].payload["custom"] == "value"


def test_generic_handles_none_inputs():
    events = GenericAdapter().translate({"type": "tool_call", "name": "x"})
    assert events[0].inputs == {}


# ----------------------------------------------------------------------
# langgraph: messy shapes
# ----------------------------------------------------------------------
def test_langgraph_handles_non_dict_node_payload():
    events = LangGraphAdapter().translate({"node": "just a string"})
    assert events[0].kind is EventKind.NOTE
    assert events[0].payload["value"] == "just a string"


def test_langgraph_handles_empty_payload():
    events = LangGraphAdapter().translate({"node": {}})
    assert events == []


def test_langgraph_handles_plain_text_content():
    events = LangGraphAdapter().translate(
        {"agent": {"messages": [{"type": "ai", "content": "plain text"}]}}
    )
    assert events[0].kind is EventKind.LLM_CALL
    assert events[0].outputs["content"] == "plain text"


def test_langgraph_handles_content_block_list_without_tool_use():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {"type": "ai", "content": [{"type": "text", "text": "hello"}]}
                ]
            }
        }
    )
    assert events[0].kind is EventKind.NOTE


def test_langgraph_handles_tool_call_with_args():
    events = LangGraphAdapter().translate(
        {"node": {"tools": [{"name": "kb.search", "args": {"q": "x"}}]}}
    )
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "x"}


def test_langgraph_handles_tool_call_with_non_dict_args():
    events = LangGraphAdapter().translate(
        {"node": {"tools": [{"name": "kb.search", "args": "oops"}]}}
    )
    assert events[0].inputs == {"value": "oops"}


def test_langgraph_handles_human_message():
    events = LangGraphAdapter().translate(
        {"agent": {"messages": [{"type": "human", "content": "hello"}]}}
    )
    assert events[0].kind is EventKind.NOTE


def test_langgraph_handles_non_dict_message():
    events = LangGraphAdapter().translate({"agent": {"messages": ["a string"]}})
    assert events[0].kind is EventKind.NOTE


def test_langgraph_extracts_model_name():
    events = LangGraphAdapter().translate(
        {
            "agent": {
                "messages": [
                    {
                        "type": "ai",
                        "content": "x",
                        "response_metadata": {"model_name": "some-model"},
                    }
                ]
            }
        }
    )
    assert events[0].payload["model"] == "some-model"


def test_langgraph_rejects_non_mapping():
    with pytest.raises(AdapterError):
        LangGraphAdapter().translate([1, 2, 3])


# ----------------------------------------------------------------------
# openai agents: messy shapes
# ----------------------------------------------------------------------
def test_openai_handles_bytes_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "x", "arguments": b'{"a": 1}'}
    )
    assert events[0].inputs == {"a": 1}


def test_openai_handles_non_json_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "x", "arguments": "not json at all"}
    )
    assert events[0].inputs == {"_raw": "not json at all"}


def test_openai_handles_json_array_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "x", "arguments": "[1, 2]"}
    )
    assert events[0].inputs == {"value": [1, 2]}


def test_openai_handles_none_arguments():
    events = OpenAIAgentsAdapter().translate(
        {"type": "tool_call", "name": "x", "arguments": None}
    )
    assert events[0].inputs == {}


def test_openai_handles_none_event():
    assert OpenAIAgentsAdapter().translate(None) == []


def test_openai_handles_unknown_dict_type():
    events = OpenAIAgentsAdapter().translate({"type": "brand_new_thing"})
    assert events[0].kind is EventKind.NOTE


def test_openai_handles_run_item_wrapper():
    class Payload:
        pass

    class Wrapper:
        name = "tool_call_item"
        payload = Payload()

    events = OpenAIAgentsAdapter().translate(Wrapper())
    assert events[0].kind is EventKind.NOTE


def test_openai_handles_object_with_model_dump():
    class Thing:
        def model_dump(self, mode=None):
            return {"type": "tool_call", "name": "x", "arguments": '{"a":1}'}

    events = OpenAIAgentsAdapter().translate(Thing())
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "x"

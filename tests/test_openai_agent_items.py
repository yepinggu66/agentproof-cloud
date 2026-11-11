"""The OpenAI Agents SDK path that handles real run-item objects.

The SDK hands out pydantic-style objects, not dicts. This exercises that
branch: ``ToolCallItem``, ``ToolCallOutputItem``, ``MessageOutputItem``, and
the run-item wrappers, using stand-ins with the same attribute names.
"""

from __future__ import annotations

from agentproof.capture.adapters import OpenAIAgentsAdapter
from agentproof.capture.events import EventKind


class ToolCallItem:
    def __init__(self, name, arguments, call_id="c1"):
        self.name = name
        self.arguments = arguments
        self.call_id = call_id


class ToolCallOutputItem:
    def __init__(self, name, output, call_id="c1"):
        self.name = name
        self.output = output
        self.call_id = call_id


class RawItem:
    def __init__(self, role, content):
        self.role = role
        self.content = content


class MessageOutputItem:
    def __init__(self, raw_item):
        self.raw_item = raw_item


class RunItemStarted:
    def __init__(self, name, payload):
        self.name = name
        self.payload = payload


def test_tool_call_item_is_translated():
    events = OpenAIAgentsAdapter().translate(
        ToolCallItem("kb.search", '{"q": "refund"}')
    )
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"
    assert events[0].inputs == {"q": "refund"}
    assert events[0].payload["call_id"] == "c1"


def test_tool_call_output_item_is_translated():
    events = OpenAIAgentsAdapter().translate(
        ToolCallOutputItem("kb.search", {"hits": 3})
    )
    assert events[0].kind is EventKind.TOOL_RESULT
    assert events[0].outputs == {"output": {"hits": 3}}


def test_message_output_item_is_translated():
    events = OpenAIAgentsAdapter().translate(
        MessageOutputItem(RawItem("assistant", "hello"))
    )
    assert events[0].kind is EventKind.LLM_CALL
    assert events[0].outputs == {"content": "hello"}
    assert events[0].payload["role"] == "assistant"


def test_run_item_wrapper_unwraps_its_payload():
    events = OpenAIAgentsAdapter().translate(
        RunItemStarted("tool_call_item", ToolCallItem("kb.search", '{"q":"x"}'))
    )
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"


def test_run_item_wrapper_without_payload_becomes_a_note():
    class RunItemCompleted:
        def __init__(self):
            self.name = "tool_call_item"
            self.payload = None

    events = OpenAIAgentsAdapter().translate(RunItemCompleted())
    assert events[0].kind is EventKind.NOTE
    assert events[0].payload["wrapper"] == "RunItemCompleted"


def test_unknown_object_type_becomes_a_note():
    class Mystery:
        pass

    events = OpenAIAgentsAdapter().translate(Mystery())
    assert events[0].kind is EventKind.NOTE
    assert events[0].payload["unhandled_type"] == "Mystery"


def test_object_with_dict_method_is_projected():
    class Legacy:
        def dict(self):
            return {"type": "tool_call", "name": "x", "arguments": '{"a":1}'}

    events = OpenAIAgentsAdapter().translate(Legacy())
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].inputs == {"a": 1}


def test_projection_without_explicit_type_is_inferred():
    class NoType:
        def model_dump(self, mode=None):
            return {"name": "kb.search", "arguments": '{"q":"x"}'}

    events = OpenAIAgentsAdapter().translate(NoType())
    assert events[0].kind is EventKind.TOOL_CALL
    assert events[0].action == "kb.search"


def test_projection_infers_tool_output():
    class NoType:
        def model_dump(self, mode=None):
            return {"name": "kb.search", "output": "done"}

    events = OpenAIAgentsAdapter().translate(NoType())
    assert events[0].kind is EventKind.TOOL_RESULT


def test_projection_infers_message():
    class NoType:
        def model_dump(self, mode=None):
            return {"content": "hello"}

    events = OpenAIAgentsAdapter().translate(NoType())
    assert events[0].kind is EventKind.LLM_CALL


def test_projection_that_raises_falls_back_gracefully():
    class Broken:
        def model_dump(self, mode=None):
            raise RuntimeError("nope")

    events = OpenAIAgentsAdapter().translate(Broken())
    assert events[0].kind is EventKind.NOTE

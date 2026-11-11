"""Trace capture: normalized events, recorders, and framework adapters."""

from .adapters import (
    AdapterError,
    EventAdapter,
    GenericAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    get_adapter,
)
from .events import EVENT_KINDS, AgentEvent, EventKind
from .recorder import Recorder, TraceWriter, iter_trace, read_trace

__all__ = [
    "AdapterError",
    "EventAdapter",
    "GenericAdapter",
    "LangGraphAdapter",
    "OpenAIAgentsAdapter",
    "get_adapter",
    "EVENT_KINDS",
    "AgentEvent",
    "EventKind",
    "Recorder",
    "TraceWriter",
    "iter_trace",
    "read_trace",
]

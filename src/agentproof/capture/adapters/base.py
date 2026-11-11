"""Adapter protocol.

An adapter's only job is to translate a framework's native events into
:class:`~agentproof.capture.events.AgentEvent`. It must not contain policy
logic, vendor-specific field names in its output, or any dependency on a
specific model provider.

If you write an adapter, keep it in this shape: a pure function from a
framework event dict to zero or more :class:`AgentEvent` objects. No I/O, no
network, no global state. That makes it trivially testable and guarantees the
core stays vendor-neutral.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..events import AgentEvent

__all__ = ["EventAdapter", "AdapterError"]


class AdapterError(Exception):
    """Raised when an adapter cannot interpret an incoming event."""


@runtime_checkable
class EventAdapter(Protocol):
    """Translates framework-native events into the neutral event model."""

    #: Short identifier, e.g. "langgraph", "openai-agents", "generic".
    name: str

    def translate(self, event: dict[str, Any]) -> list[AgentEvent]:
        """Translate one native event into zero or more neutral events."""
        ...

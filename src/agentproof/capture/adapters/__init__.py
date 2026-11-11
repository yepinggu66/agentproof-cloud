"""Adapters that translate framework-native events into the neutral model."""

from .base import AdapterError, EventAdapter
from .generic import GenericAdapter
from .langgraph import LangGraphAdapter
from .openai_agents import OpenAIAgentsAdapter

__all__ = [
    "AdapterError",
    "EventAdapter",
    "GenericAdapter",
    "LangGraphAdapter",
    "OpenAIAgentsAdapter",
    "get_adapter",
]

_REGISTRY = {
    "generic": GenericAdapter,
    "langgraph": LangGraphAdapter,
    "openai-agents": OpenAIAgentsAdapter,
    "openai_agents": OpenAIAgentsAdapter,
}


def get_adapter(name: str) -> EventAdapter:
    """Return an adapter instance by name.

    Unknown names fall back to the generic adapter rather than raising, so a
    typo in a config file degrades to "capture everything loosely" instead of
    crashing a production run.
    """
    key = str(name or "generic").strip().lower()
    factory = _REGISTRY.get(key, GenericAdapter)
    return factory()

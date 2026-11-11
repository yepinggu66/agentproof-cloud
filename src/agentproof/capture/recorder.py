"""Trace recording.

The recorder writes a JSONL stream of normalized events. JSONL is chosen on
purpose: it is append-only, streamable, greppable, diffable, and a reviewer
can read it without any tooling at all.

Recording is a *separate* concern from deciding. The recorder observes; the
gate decides and signs. Keeping them apart means you can record a
production trace without any signing key present on the box, and replay it
later against a policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from .events import AgentEvent, EventKind

__all__ = ["Recorder", "read_trace", "TraceWriter"]


class Recorder:
    """Collects events in memory and/or writes them to a JSONL file."""

    def __init__(self, path: str | Path | None = None, *, keep_in_memory: bool = True):
        self.path = Path(path) if path else None
        self.keep_in_memory = keep_in_memory
        self._events: list[AgentEvent] = []
        self._handle = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self.path.open("w", encoding="utf-8")

    # -- context manager -------------------------------------------------
    def __enter__(self) -> "Recorder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- recording -------------------------------------------------------
    def record(self, event: AgentEvent) -> AgentEvent:
        if self.keep_in_memory:
            self._events.append(event)
        if self._handle:
            self._handle.write(
                json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
            )
            self._handle.flush()
        return event

    def record_many(self, events: Iterable[AgentEvent]) -> None:
        for event in events:
            self.record(event)

    def note(self, text: str, **tags: str) -> AgentEvent:
        """Record a free-form annotation."""
        return self.record(
            AgentEvent(
                kind=EventKind.NOTE,
                ts=AgentEvent.now_ts(),
                payload={"text": text},
                tags=list(tags),
            )
        )

    @property
    def events(self) -> list[AgentEvent]:
        return list(self._events)

    def close(self) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None

    def save(self, path: str | Path) -> Path:
        """Write the in-memory events to a JSONL file."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for event in self._events:
                fh.write(
                    json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True)
                    + "\n"
                )
        return out


class TraceWriter:
    """Streams events to an open JSONL file handle."""

    def __init__(self, handle: Any):
        self._handle = handle

    def write(self, event: AgentEvent) -> None:
        self._handle.write(
            json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
        )
        self._handle.flush()

    def write_many(self, events: Iterable[AgentEvent]) -> None:
        for event in events:
            self.write(event)


def read_trace(path: str | Path) -> list[AgentEvent]:
    """Read a JSONL trace file into a list of events.

    A UTF-8 BOM is accepted, because editors on Windows like to add one; apart
    from that the file must be UTF-8. A malformed line is reported with the
    file and line number rather than as a bare ``JSONDecodeError``.
    """
    trace_path = Path(path)
    events: list[AgentEvent] = []
    for lineno, line in enumerate(
        trace_path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError as exc:
            raise ValueError(
                f"{trace_path}: line {lineno} is not valid JSON: {exc}"
            ) from exc
        events.append(AgentEvent.from_dict(payload))
    return events


def iter_trace(path: str | Path) -> Iterator[AgentEvent]:
    """Stream a JSONL trace file event by event (a UTF-8 BOM is accepted)."""
    trace_path = Path(path)
    with trace_path.open("r", encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except ValueError as exc:
                raise ValueError(
                    f"{trace_path}: line {lineno} is not valid JSON: {exc}"
                ) from exc
            yield AgentEvent.from_dict(payload)

"""Regression case generation and replay."""

from __future__ import annotations

import pytest

from agentproof.capture.events import AgentEvent, EventKind
from agentproof.regression import (
    compare_actions,
    generate_case,
    generate_cases,
    load_case,
    replay,
)


def _event(kind, action="", inputs=None, outputs=None, error=None, agent="a", tags=None):
    return AgentEvent(
        kind=kind,
        ts=AgentEvent.now_ts(),
        agent=agent,
        action=action,
        inputs=inputs or {},
        outputs=outputs or {},
        error=error,
        tags=tags or [],
    )


TRACE = [
    _event(EventKind.AGENT_START),
    _event(EventKind.LLM_CALL, outputs={"content": "thinking"}),
    _event(EventKind.TOOL_CALL, action="kb.search", inputs={"q": "refund policy"}),
    _event(EventKind.TOOL_RESULT, action="kb.search", outputs={"hits": 3}),
    _event(
        EventKind.TOOL_CALL,
        action="db.write",
        inputs={"sql": "UPDATE ..."},
    ),
    _event(
        EventKind.TOOL_RESULT,
        action="db.write",
        error="permission denied",
    ),
    _event(EventKind.ERROR, action="db.write", error="permission denied"),
]


# ----------------------------------------------------------------------
# generation
# ----------------------------------------------------------------------
def test_case_is_generated_from_a_trace_with_tool_calls():
    case = generate_case(TRACE, source_trace="t.jsonl")
    assert case is not None
    assert len(case.steps) == 2
    assert case.steps[0]["action"] == "kb.search"
    assert case.steps[0]["inputs"] == {"q": "refund policy"}
    assert case.created_from == "error"


def test_no_case_without_tool_calls():
    trace = [_event(EventKind.LLM_CALL)]
    assert generate_case(trace) is None


def test_generated_case_is_valid_yaml(tmp_path):
    case = generate_case(TRACE)
    path = case.save(tmp_path / "case.yaml")

    reloaded = load_case(path)
    assert reloaded.name == case.name
    assert len(reloaded.steps) == len(case.steps)
    assert reloaded.assertions == case.assertions


def test_error_trace_gets_a_no_errors_assertion():
    """A case from a failing trace asserts the bug does not recur."""
    case = generate_case(TRACE)
    kinds = [a["type"] for a in case.assertions]
    assert "action_sequence" in kinds
    assert "no_errors" in kinds


def test_original_error_is_kept_as_context_not_asserted():
    """The original failure is preserved for a human, not asserted on.

    Asserting both 'no errors' and 'these actions errored' would be
    self-contradictory.
    """
    case = generate_case(TRACE)
    assert "error_action_sequence" not in [a["type"] for a in case.assertions]
    assert case.context["original_errors"]
    assert case.context["original_errors"][0]["action"] == "db.write"
    assert "permission denied" in case.context["original_errors"][0]["error"]


def test_replay_fails_against_the_still_broken_behaviour():
    """Replaying the recorded (broken) behaviour must fail the case."""
    case = generate_case(TRACE)

    def target(step):
        if step["action"] == "db.write":
            return {"decision": "allow", "error": "permission denied"}
        expect = step.get("expect") or {}
        return {"decision": expect.get("decision", "allow")}

    result = replay(case, target)
    assert not result.passed
    assert any("no errors" in f for f in result.assertion_failures)


def test_expected_failure_tag_is_honoured():
    trace = [
        _event(EventKind.TOOL_CALL, action="kb.search", tags=["expected-failure"]),
    ]
    case = generate_case(trace)
    assert case.created_from == "expected-failure"


def test_cases_are_split_per_agent():
    trace = [
        _event(EventKind.TOOL_CALL, action="a.one", agent="agent-a"),
        _event(EventKind.TOOL_CALL, action="b.two", agent="agent-b"),
    ]
    cases = generate_cases(trace)
    assert len(cases) == 2
    assert {c.agent for c in cases} == {"agent-a", "agent-b"}


# ----------------------------------------------------------------------
# replay
# ----------------------------------------------------------------------
def test_replay_passes_against_matching_target():
    case = generate_case(TRACE)

    def target(step):
        expect = step.get("expect") or {}
        return {"decision": expect.get("decision", "allow")}

    result = replay(case, target)
    assert result.passed
    assert result.render().startswith("case   :")


def test_replay_detects_a_changed_decision():
    case = generate_case(TRACE)

    def target(step):
        # The second step now behaves differently than recorded.
        if step["action"] == "db.write":
            return {"decision": "deny"}
        expect = step.get("expect") or {}
        return {"decision": expect.get("decision", "allow")}

    result = replay(case, target)
    assert not result.passed
    assert any("decision differs" in d for s in result.steps for d in s.diff)


def test_replay_detects_a_changed_action_sequence():
    case = generate_case(TRACE)

    def target(step):
        expect = step.get("expect") or {}
        return {"decision": expect.get("decision", "allow")}

    # Simulate the target taking a different path by dropping a step.
    trimmed = type(case)(
        name=case.name,
        agent=case.agent,
        source_trace=case.source_trace,
        created_from=case.created_from,
        description=case.description,
        steps=case.steps[:1],
        assertions=case.assertions,
        context=case.context,
    )

    result = replay(trimmed, target)
    assert not result.passed
    assert any("action sequence diverges" in f for f in result.assertion_failures)


def test_crashing_target_is_a_failure_not_a_crash():
    case = generate_case(TRACE)

    def target(step):
        raise RuntimeError("model timeout")

    result = replay(case, target)
    assert not result.passed
    assert any(s.error for s in result.steps)


def test_compare_actions_reports_first_divergence():
    differences = compare_actions(["a", "b", "c"], ["a", "x", "c"])
    assert len(differences) == 1
    assert "position 1" in differences[0]

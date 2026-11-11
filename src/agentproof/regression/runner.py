"""Replay a regression case and diff the result.

The runner drives a *target* — a callable that receives a step and returns
what happened — and compares the outcome against the case's expectations.

Why a callable and not a framework
----------------------------------
Because a regression test that can only run against one framework is a
regression test that dies when you change frameworks. The runner takes any
callable ``target(step) -> {"decision": ..., "outputs": ..., "error": ...}``.
Wiring it to LangGraph, OpenAI Agents, or your own code is a few lines, and
the comparison logic stays identical.

Comparison is field-by-field and reports the *diff*, not just pass/fail. An
auditor wants to see exactly which decision changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .generate import RegressionCase

__all__ = ["ReplayResult", "StepOutcome", "replay", "compare_actions"]

#: A target receives one step dict and returns a dict with optional keys
#: ``decision``, ``outputs``, ``error``.
Target = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class StepOutcome:
    """What happened when one step ran."""

    index: int
    action: str
    expected_decision: str
    actual_decision: str
    expected_outputs: Any = None
    actual_outputs: Any = None
    error: str | None = None
    diff: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.diff

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "action": self.action,
            "expected_decision": self.expected_decision,
            "actual_decision": self.actual_decision,
            "error": self.error,
            "diff": self.diff,
            "passed": self.passed,
        }


@dataclass
class ReplayResult:
    """The outcome of a full replay."""

    case_name: str
    steps: list[StepOutcome] = field(default_factory=list)
    assertion_failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.steps) and not self.assertion_failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case_name,
            "passed": self.passed,
            "steps": [s.to_dict() for s in self.steps],
            "assertion_failures": self.assertion_failures,
        }

    def render(self) -> str:
        lines = [f"case   : {self.case_name}", f"result : {'PASS' if self.passed else 'FAIL'}"]
        for step in self.steps:
            mark = "ok  " if step.passed else "FAIL"
            lines.append(f"  [{mark}] step {step.index} {step.action}")
            for difference in step.diff:
                lines.append(f"         {difference}")
        for failure in self.assertion_failures:
            lines.append(f"  [FAIL] assertion: {failure}")
        return "\n".join(lines)


def compare_actions(expected: list[str], actual: list[str]) -> list[str]:
    """Compare two action sequences, reporting the first divergence clearly."""
    differences: list[str] = []
    for index in range(max(len(expected), len(actual))):
        exp = expected[index] if index < len(expected) else "<missing>"
        act = actual[index] if index < len(actual) else "<missing>"
        if exp != act:
            differences.append(
                f"action sequence diverges at position {index}: "
                f"expected {exp!r}, got {act!r}"
            )
    return differences


def replay(case: RegressionCase, target: Target) -> ReplayResult:
    """Replay ``case`` against ``target`` and report the differences."""
    result = ReplayResult(case_name=case.name)
    actual_actions: list[str] = []

    for index, step in enumerate(case.steps):
        action = str(step.get("action") or "")
        expect = step.get("expect") or {}
        expected_decision = str(expect.get("decision") or "allow")
        expected_outputs = expect.get("outputs")

        try:
            raw = target({**step, "action": action}) or {}
        except Exception as exc:  # noqa: BLE001 - a crashing target is a failure
            raw = {"decision": "error", "error": f"{type(exc).__name__}: {exc}"}

        actual_decision = str(raw.get("decision") or "allow")
        actual_outputs = raw.get("outputs")
        error = raw.get("error")

        actual_actions.append(action)

        differences: list[str] = []
        if actual_decision != expected_decision:
            differences.append(
                f"decision differs: expected {expected_decision!r}, "
                f"got {actual_decision!r}"
            )
        if expected_outputs is not None and actual_outputs != expected_outputs:
            differences.append(
                f"outputs differ: expected {expected_outputs!r}, got {actual_outputs!r}"
            )

        result.steps.append(
            StepOutcome(
                index=index,
                action=action,
                expected_decision=expected_decision,
                actual_decision=actual_decision,
                expected_outputs=expected_outputs,
                actual_outputs=actual_outputs,
                error=error,
                diff=differences,
            )
        )

    # assertions
    for assertion in case.assertions:
        kind = str(assertion.get("type") or "")
        if kind == "action_sequence":
            expected = list(assertion.get("value") or [])
            differences = compare_actions(expected, actual_actions)
            result.assertion_failures.extend(differences)
        elif kind == "no_errors":
            failed = [s for s in result.steps if s.error]
            if failed:
                result.assertion_failures.append(
                    "expected no errors, but steps "
                    + ", ".join(str(s.index) for s in failed)
                    + " raised one"
                )
        elif kind == "error_action_sequence":
            expected = list(assertion.get("value") or [])
            actual = [s.action for s in result.steps if s.error]
            differences = compare_actions(expected, actual)
            result.assertion_failures.extend(differences)

    return result

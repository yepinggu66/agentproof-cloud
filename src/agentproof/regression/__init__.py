"""Regression cases: generate them from traces, replay them against a target."""

from .generate import RegressionCase, generate_case, generate_cases, load_case
from .runner import ReplayResult, StepOutcome, compare_actions, replay

__all__ = [
    "RegressionCase",
    "generate_case",
    "generate_cases",
    "load_case",
    "ReplayResult",
    "StepOutcome",
    "compare_actions",
    "replay",
]

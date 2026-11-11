"""Automated PLG Customer Acquisition & Outbound Lead Scanner (`agentproof scout`)."""

from __future__ import annotations

from .scout import (
    LeadCandidate,
    ScoutSummary,
    build_outreach_package,
    discover_github_leads,
    scout_local_repositories,
)

__all__ = [
    "LeadCandidate",
    "ScoutSummary",
    "build_outreach_package",
    "discover_github_leads",
    "scout_local_repositories",
]

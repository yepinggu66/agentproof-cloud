"""Compatibility shim.

The document scanner used by the web API, the browser port and the audit tools
now lives in :mod:`agentproof.scanner.engine` — one engine, one rule catalog.
This module keeps the historical ``server.scan`` import path working.
"""

from __future__ import annotations

from agentproof.scanner.engine import (  # noqa: F401
    GRADE_ORDER,
    MAX_CONTENT_BYTES,
    SEVERITY_WEIGHT,
    Finding,
    ScanInputError,
    ScanResult,
    scan,
    scan_mcp,
    scan_python,
)

__all__ = [
    "GRADE_ORDER",
    "MAX_CONTENT_BYTES",
    "SEVERITY_WEIGHT",
    "Finding",
    "ScanInputError",
    "ScanResult",
    "scan",
    "scan_mcp",
    "scan_python",
]

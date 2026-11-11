"""agentproof — vendor-neutral regression testing and compliance evidence for AI agents.

The premise: an agent's own account of what it did is a claim, not evidence.
agentproof issues a signed decision *before* the action runs, links every
decision into an append-only hash chain, and lets anyone holding a public key
verify the result offline.
"""

__version__ = "0.2.0"

from .core import (
    Chain,
    ChainError,
    Decision,
    Policy,
    PolicyError,
    Receipt,
    VerificationResult,
    canonical_json,
    digest_bytes,
    generate_keypair,
    load_policy,
    verify_chain_file,
)
from .evidence import InsurabilityScorecard, compute_insurability_score
from .runtime import PolicyDeniedError, RuntimeGate
from .scanner import ScanReport, generate_starter_policy, run_workspace_scan

__all__ = [
    "__version__",
    "Chain",
    "ChainError",
    "Decision",
    "InsurabilityScorecard",
    "Policy",
    "PolicyDeniedError",
    "PolicyError",
    "Receipt",
    "RuntimeGate",
    "ScanReport",
    "VerificationResult",
    "canonical_json",
    "compute_insurability_score",
    "digest_bytes",
    "generate_keypair",
    "generate_starter_policy",
    "load_policy",
    "run_workspace_scan",
    "verify_chain_file",
]

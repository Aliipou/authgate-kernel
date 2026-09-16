"""
Compatibility shim — formerly `authgate.integrations.fdk`.

Prefer `authgate.integrations.legitimacy`. This module re-exports the same API
so existing imports and examples keep working.
"""
from __future__ import annotations

from authgate.integrations.legitimacy import (  # noqa: F401
    PolicyContractError,
    PolicyDecision,
    Verdict,
    decide_freedom_formal,
    enforce_freedom_formal,
    enforce_legitimacy,
    parse_policy_decision,
)

__all__ = [
    "PolicyContractError",
    "PolicyDecision",
    "Verdict",
    "decide_freedom_formal",
    "enforce_freedom_formal",
    "enforce_legitimacy",
    "parse_policy_decision",
]

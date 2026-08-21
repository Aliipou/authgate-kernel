"""
authgate.integrations — seams to upstream / co-equal evaluators.

Composition model (decision-os): lattice meet of DENY-only evaluators.
AuthGate CallGate is the authority evaluator. Legitimacy is optional and
never grants.

  - `legitimacy` — PolicyDecision seam + Freedom Formal adapter (preferred)
  - `fdk` — deprecated alias re-exporting `legitimacy`
"""
from __future__ import annotations

from authgate.integrations import legitimacy as legitimacy

__all__ = ["legitimacy"]

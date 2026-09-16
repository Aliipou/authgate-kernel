"""Freedom Formal research package — enforceable skill A1–A5 (no GAP)."""
from __future__ import annotations

from authgate.research.freedom_formal.axioms import (
    CANONICAL_CONSTITUTION,
    FreedomFormalEvaluator,
)
from authgate.research.freedom_formal.pipeline import (
    PipelineResult,
    compose_legitimacy_then_authority,
)
from authgate.research.freedom_formal.scenarios import catalog, unique_need_scenarios
from authgate.research.freedom_formal.types import (
    AxiomId,
    Claim,
    Evaluation,
    Finding,
    Strength,
    Verdict,
)

__all__ = [
    "CANONICAL_CONSTITUTION",
    "AxiomId",
    "Claim",
    "Evaluation",
    "Finding",
    "FreedomFormalEvaluator",
    "PipelineResult",
    "Strength",
    "Verdict",
    "catalog",
    "compose_legitimacy_then_authority",
    "unique_need_scenarios",
]

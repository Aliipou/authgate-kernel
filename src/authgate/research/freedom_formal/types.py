"""Shared types for the Freedom Formal research evaluator.

Every skill axiom maps to a STRUCTURAL check. No GAP outcomes.
Theological wording is reduced to machine predicates (see axioms.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AxiomId(StrEnum):
    """Skill numbering — NOT AuthGate AXIOMATIC_FOUNDATION A1–A7."""

    A1_TAWHID = "A1_TAWHID"
    A2_MAAD = "A2_MAAD"
    A3_NUBUWWAT = "A3_NUBUWWAT"
    A4_ADL = "A4_ADL"
    A5_IMAMAT = "A5_IMAMAT"
    M1_EXPRESSIBLE = "M1_EXPRESSIBLE"
    M2_CONSISTENT = "M2_CONSISTENT"
    M3_MINIMAL = "M3_MINIMAL"


class Strength(StrEnum):
    """All checks are STRUCTURAL in this experiment (no GAP / SHADOW denies)."""

    STRUCTURAL = "STRUCTURAL"


class Verdict(StrEnum):
    """Legitimacy verdict. ALLOW never grants authority — AuthGate still decides."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"


@dataclass(frozen=True)
class Finding:
    axiom: AxiomId
    strength: Strength
    ok: bool
    detail: str
    solution: str = ""

    def as_trace(self) -> str:
        status = "ok" if self.ok else "violated"
        return f"{self.axiom.value}:{self.strength.value}:{status}:{self.detail}"


@dataclass(frozen=True)
class Claim:
    """Claim surface for compatibility analysis + AuthGate-gap scenarios.

    Fields marked *extra* are the Freedom Formal predicates AuthGate's capability
    gate does not check today.
    """

    action_id: str
    actor_id: str
    actor_is_machine: bool = False
    actor_has_human_owner: bool = True
    # AuthGate-overlapping
    governs_humans: tuple[str, ...] = ()
    claims_own_human: bool = False
    increases_machine_sovereignty: bool = False
    # A2 Ma'ad → accountability / anti-endgame
    audit_bound: bool = True
    clears_audit_trail: bool = False
    known_audit_deadline: bool = False  # End Game: actor knows when review ends
    # A3 Nubuwwat → sealed constitution / no compulsory guide
    compulsory_guide: bool = False
    declares_new_formal_system: bool = False
    constitution_digest: str = "freedom-formal-v1"
    # A4 Adl → personal responsibility
    liability_shifted_to: str | None = None
    socializes_loss: bool = False
    # A5 Imamat → exit + optional guide when Is/Ought gap
    exit_blocked: bool = False
    return_to_freedom_blocked: bool = False
    is_ought_gap: bool = False
    guide_available: bool = True
    guide_opt_in: bool = True
    # AuthGate capability (for pipeline demos)
    has_valid_capability: bool = True
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evaluation:
    verdict: Verdict
    findings: tuple[Finding, ...]

    @property
    def axiom_trace(self) -> tuple[str, ...]:
        return tuple(f.as_trace() for f in self.findings)

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(f.detail for f in self.findings if not f.ok)

    @property
    def violated_axioms(self) -> tuple[AxiomId, ...]:
        return tuple(f.axiom for f in self.findings if not f.ok)

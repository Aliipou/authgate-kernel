"""Skill A1–A5 as enforceable structural solutions (no GAP).

Each axiom has a machine predicate. Theological content is reduced to
checks that can pass/fail on a Claim. See SOLUTIONS in each check docstring.
"""
from __future__ import annotations

from authgate.research.freedom_formal.types import (
    AxiomId,
    Claim,
    Evaluation,
    Finding,
    Strength,
    Verdict,
)

# Sealed constitution digest for this research formal system (A3).
CANONICAL_CONSTITUTION = "freedom-formal-v1"


def _ok(axiom: AxiomId, detail: str, solution: str) -> Finding:
    return Finding(axiom, Strength.STRUCTURAL, True, detail, solution)


def _bad(axiom: AxiomId, detail: str, solution: str) -> Finding:
    return Finding(axiom, Strength.STRUCTURAL, False, detail, solution)


def check_a1_tawhid(claim: Claim) -> Finding:
    """A1 — no human/machine holds ultimate authority over a human.

    Solution: ¬UltAuth encoded as:
      - machine must not govern humans
      - no human-owns-human claim
      - no machine-sovereignty escalation
      - every machine has a human owner (no ambient machine UltAuth)
    """
    sol = "deny UltAuth proxies: dominion, human-ownership, sovereignty escalate, ownerless machine"
    if claim.claims_own_human:
        return _bad(AxiomId.A1_TAWHID, "human/machine claims ownership of a human", sol)
    if claim.governs_humans:
        return _bad(
            AxiomId.A1_TAWHID,
            f"actor governs humans {claim.governs_humans}",
            sol,
        )
    if claim.increases_machine_sovereignty:
        return _bad(AxiomId.A1_TAWHID, "action increases machine sovereignty", sol)
    if claim.actor_is_machine and not claim.actor_has_human_owner:
        return _bad(AxiomId.A1_TAWHID, "ownerless machine would hold ambient UltAuth", sol)
    return _ok(AxiomId.A1_TAWHID, "no UltAuth proxy detected", sol)


def check_a2_maad(claim: Claim) -> Finding:
    """A2 — accountability + hidden endgame (anti End Game exploit).

    Solution (computable reduction of معاد):
      - every Act must bind to an audit answer record (Ans)
      - clearing the audit trail is denied
      - known_audit_deadline denied: actor must not optimize crime for a known
        review cutoff (Hidden(t) ≈ review horizon not adversarially knowable)
    """
    sol = "require audit_bound; deny clears_audit_trail; deny known_audit_deadline"
    if not claim.audit_bound:
        return _bad(AxiomId.A2_MAAD, "action not bound to accountability audit", sol)
    if claim.clears_audit_trail:
        return _bad(AxiomId.A2_MAAD, "action clears or truncates audit trail", sol)
    if claim.known_audit_deadline:
        return _bad(
            AxiomId.A2_MAAD,
            "actor knows audit/review deadline (End Game exploit)",
            sol,
        )
    return _ok(AxiomId.A2_MAAD, "accountability bound; endgame unknown", sol)


def check_a3_nubuwwat(claim: Claim) -> Finding:
    """A3 — sealed unique formal system + no compulsory guidance.

    Solution (computable reduction of نبوت):
      - constitution_digest must equal sealed CANONICAL_CONSTITUTION
      - declares_new_formal_system denied (no rival axiom set at runtime)
      - compulsory_guide denied; guide may exist only with opt-in
    """
    sol = "seal constitution digest; deny rival formal systems; deny compulsory guide"
    if claim.declares_new_formal_system:
        return _bad(AxiomId.A3_NUBUWWAT, "declares a new/rival formal system", sol)
    if claim.constitution_digest != CANONICAL_CONSTITUTION:
        return _bad(
            AxiomId.A3_NUBUWWAT,
            f"constitution digest {claim.constitution_digest!r} ≠ sealed {CANONICAL_CONSTITUTION!r}",
            sol,
        )
    if claim.compulsory_guide:
        return _bad(AxiomId.A3_NUBUWWAT, "compulsory guidance (لا اکراه violated)", sol)
    if claim.is_ought_gap and claim.guide_available and not claim.guide_opt_in:
        return _bad(
            AxiomId.A3_NUBUWWAT,
            "guide forced without opt-in while Is/Ought gap open",
            sol,
        )
    return _ok(AxiomId.A3_NUBUWWAT, "sealed constitution; guidance non-compulsory", sol)


def check_a4_adl(claim: Claim) -> Finding:
    """A4 — personal responsibility for acts (عدل).

    Solution:
      - liability must stay on actor (no liability_shifted_to other)
      - socializes_loss denied (State-like cost externalization proxy)
    """
    sol = "Resp(actor, act): deny liability shift and loss socialization"
    if claim.liability_shifted_to and claim.liability_shifted_to != claim.actor_id:
        return _bad(
            AxiomId.A4_ADL,
            f"liability shifted to {claim.liability_shifted_to!r}, not actor",
            sol,
        )
    if claim.socializes_loss:
        return _bad(AxiomId.A4_ADL, "action socializes loss onto non-responsible parties", sol)
    return _ok(AxiomId.A4_ADL, "responsibility remains with actor", sol)


def check_a5_imamat(claim: Claim) -> Finding:
    """A5 — exit always open; guide available (opt-in) when Is/Ought gap.

    Solution:
      - exit_blocked / return_to_freedom_blocked denied
      - if is_ought_gap: guide_available required (but opt-in — see A3)
    """
    sol = "CanExit ∧ CanReturnFree; Guide available (opt-in) when Gap(Is,Ought)"
    if claim.exit_blocked:
        return _bad(AxiomId.A5_IMAMAT, "exit from system/relationship blocked", sol)
    if claim.return_to_freedom_blocked:
        return _bad(AxiomId.A5_IMAMAT, "return path to freedom blocked", sol)
    if claim.is_ought_gap and not claim.guide_available:
        return _bad(
            AxiomId.A5_IMAMAT,
            "Is/Ought gap with no guide channel available",
            sol,
        )
    return _ok(AxiomId.A5_IMAMAT, "exit open; guide policy satisfied", sol)


def check_meta(claim: Claim) -> tuple[Finding, ...]:
    """M1–M3 as structural self-checks on the claim encoding."""
    findings: list[Finding] = []
    # M1 — claim is expressible as finite fields (always true if we got here)
    findings.append(
        _ok(
            AxiomId.M1_EXPRESSIBLE,
            "claim encoded in finite typed fields",
            "objective wire-expressible Claim",
        )
    )
    # M2 — no simultaneous contradictory flags we know how to detect
    contradictory = (
        claim.compulsory_guide and claim.guide_opt_in is False and claim.is_ought_gap
    )
    # Already covered in A3; M2 checks mutual exclusion: ALLOW path can't both
    # require audit and clear it.
    if claim.audit_bound and claim.clears_audit_trail:
        findings.append(
            _bad(
                AxiomId.M2_CONSISTENT,
                "audit_bound ∧ clears_audit_trail is inconsistent",
                "reject internally contradictory claims",
            )
        )
    else:
        findings.append(
            _ok(AxiomId.M2_CONSISTENT, "no detected internal contradiction", "consistency gate")
        )
    # M3 — minimal: reject claims that invent extra constitution forks
    if claim.declares_new_formal_system:
        findings.append(
            _bad(
                AxiomId.M3_MINIMAL,
                "new formal system expands axiom set without seal",
                "prefer sealed minimal Ax",
            )
        )
    else:
        findings.append(
            _ok(AxiomId.M3_MINIMAL, "sealed minimal axiom set retained", "Occam on Ax")
        )
    _ = contradictory  # documented interaction with A3
    return tuple(findings)


class FreedomFormalEvaluator:
    """DENY-only legitimacy evaluator for the Freedom Formal System skill."""

    def evaluate(self, claim: Claim) -> Evaluation:
        findings = (
            check_a1_tawhid(claim),
            check_a2_maad(claim),
            check_a3_nubuwwat(claim),
            check_a4_adl(claim),
            check_a5_imamat(claim),
            *check_meta(claim),
        )
        if any(not f.ok for f in findings):
            return Evaluation(Verdict.DENY, findings)
        return Evaluation(Verdict.ALLOW, findings)

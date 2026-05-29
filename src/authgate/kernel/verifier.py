"""
FreedomVerifier — deterministic capability-governance permission gate.

Checks exactly four things:
  1. Hard sovereignty/corrigibility flags (instant FORBIDDEN)
  2. Machine ownership: every machine has a registered human owner
  3. Machine dominion: no machine governs any human
  4. Resource access via rights claims (read/write/delegate)

No manipulation detection. No synthesis engine. No conflict queue.
Those are extension concerns. This gate is formally verifiable and has
no LLM dependencies or external I/O.

Wire-in:
    verifier = FreedomVerifier(registry)
    result = verifier.verify(action)
    if not result.permitted:
        agent.halt(result.summary())
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from authgate.kernel.entities import Entity, Resource
from authgate.kernel.hooks import HookRegistry, VerificationEvent
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.tracing import TraceCollector

_log = logging.getLogger("authgate.kernel.verifier")

CONFIDENCE_WARN_THRESHOLD = 0.8


@dataclass
class Action:
    """
    A typed action an agent requests to execute.
    All fields are explicitly typed — no vague string resources.
    Only machine-context ResourceType values are valid.
    """
    action_id: str
    actor: Entity
    description: str = ""
    resources_read: list[Resource] = field(default_factory=list)
    resources_write: list[Resource] = field(default_factory=list)
    resources_delegate: list[Resource] = field(default_factory=list)
    governs_humans: list[Entity] = field(default_factory=list)
    argument: str = ""

    increases_machine_sovereignty: bool = False
    resists_human_correction: bool = False
    bypasses_verifier: bool = False
    weakens_verifier: bool = False
    disables_corrigibility: bool = False
    machine_coalition_dominion: bool = False
    coerces: bool = False
    deceives: bool = False
    self_modification_weakens_verifier: bool = False
    machine_coalition_reduces_freedom: bool = False


@dataclass(frozen=True)
class VerificationResult:
    action_id: str
    permitted: bool
    violations: tuple[str, ...]
    warnings: tuple[str, ...]
    confidence: float
    requires_human_arbitration: bool
    manipulation_score: float  # always 0.0 from kernel; set by ExtendedFreedomVerifier

    def summary(self) -> str:
        status = "PERMITTED" if self.permitted else "BLOCKED"
        lines = [
            f"[{status}] {self.action_id} "
            f"(confidence={self.confidence:.2f}, manipulation={self.manipulation_score:.2f})"
        ]
        for v in self.violations:
            lines.append(f"  VIOLATION : {v}")
        for w in self.warnings:
            lines.append(f"  WARNING   : {w}")
        if self.requires_human_arbitration:
            lines.append("  ACTION    : Human arbitration required before proceeding.")
        return "\n".join(lines)


class FreedomVerifier:
    def __init__(
        self,
        registry: OwnershipRegistry,
        audit_log: object = None,
        tracer: TraceCollector | None = None,
        freeze: bool = False,
    ) -> None:
        # freeze=False (default): live registry — mutations after construction
        # are visible to subsequent verify() calls. This is the existing behavior.
        # TOCTOU note: if the registry can be mutated between verify() calls in
        # the same logical session, use freeze=True or call registry.freeze()
        # before constructing the verifier to get a consistent snapshot.
        # freeze=True: registry is snapshot at construction time; all verify()
        # calls in this verifier see the same state regardless of later mutations.
        self.registry = registry.freeze() if freeze and not registry._frozen else registry
        self._audit_log = audit_log
        self._tracer = tracer

    def verify(self, action: Action) -> VerificationResult:
        _t0 = time.monotonic()
        violations: list[str] = []
        warnings: list[str] = []
        min_confidence = 1.0
        requires_arbitration = False

        if self._tracer:
            self._tracer.begin(action.action_id)

        # 1. Hard sovereignty/corrigibility flags
        flags = [
            (action.increases_machine_sovereignty, "increases machine sovereignty"),
            (action.resists_human_correction, "resists human correction"),
            (action.bypasses_verifier, "bypasses the Freedom Verifier"),
            (action.weakens_verifier, "weakens the Freedom Verifier"),
            (action.disables_corrigibility, "disables corrigibility"),
            (action.machine_coalition_dominion, "machine coalition seeking dominion"),
            (action.coerces, "coerces another agent (property rights violation)"),
            (action.deceives, "deceives another agent (invalid consent)"),
            (action.self_modification_weakens_verifier,
             "self-modification weakens the Freedom Verifier"),
            (action.machine_coalition_reduces_freedom, "machine coalition reduces human freedom"),
        ]
        flag_violations = [label for flag, label in flags if flag]
        for label in flag_violations:
            violations.append(f"FORBIDDEN ({label})")
        if self._tracer:
            self._tracer.record_guard(
                "sovereignty_flags",
                passed=len(flag_violations) == 0,
                detail=f"{len(flag_violations)} flags set" if flag_violations else "clear",
            )

        # 2. Machine ownership: every machine must have a registered human owner
        ownership_ok = True
        if action.actor.is_machine() and self.registry.owner_of(action.actor) is None:
            violations.append(
                f"[A4] UNOWNED_MACHINE: {action.actor.name} has no registered human owner. "
                "An ownerless machine is not permitted to act."
            )
            ownership_ok = False
        if self._tracer:
            self._tracer.record_guard(
                "machine_ownership",
                passed=ownership_ok,
                detail=action.actor.name,
            )

        # 3. Machine dominion: no machine governs any human
        dominion_violations = []
        if action.actor.is_machine():
            for human in action.governs_humans:
                msg = (
                    f"[A6] MACHINE_DOMINION: {action.actor.name} cannot govern human {human.name} "
                    "(machines have no ownership or dominion over persons)."
                )
                violations.append(msg)
                dominion_violations.append(msg)
        if self._tracer:
            self._tracer.record_guard(
                "machine_dominion",
                passed=len(dominion_violations) == 0,
                detail=f"{len(dominion_violations)} violation(s)" if dominion_violations else "clear",
            )

        # 4. Resource access checks (confidence-weighted)
        actor = action.actor

        for resource in action.resources_read:
            permitted, conf, reason = self.registry.can_act(actor, resource, "read")
            min_confidence = min(min_confidence, conf)
            if not permitted:
                violations.append(f"READ DENIED on {resource}: {reason}")
            elif conf < CONFIDENCE_WARN_THRESHOLD:
                warnings.append(
                    f"READ on {resource} allowed but contested "
                    f"(confidence={conf:.2f}). Log this access."
                )

        for resource in action.resources_write:
            permitted, conf, reason = self.registry.can_act(actor, resource, "write")
            min_confidence = min(min_confidence, conf)
            if not permitted:
                violations.append(f"WRITE DENIED on {resource}: {reason}")
            elif conf < CONFIDENCE_WARN_THRESHOLD:
                warnings.append(
                    f"WRITE on {resource} contested "
                    f"(confidence={conf:.2f}). Human confirmation recommended."
                )
                for c in self.registry.open_conflicts():
                    if c.resource == resource:
                        requires_arbitration = True
                        warnings.append(f"Conflict on {resource}: {c.description}")

        for resource in action.resources_delegate:
            permitted, conf, reason = self.registry.can_act(actor, resource, "delegate")
            min_confidence = min(min_confidence, conf)
            if not permitted:
                violations.append(f"DELEGATION DENIED on {resource}: {reason}")

        permitted = len(violations) == 0
        if self._tracer:
            self._tracer.record_guard(
                "claim_check",
                passed=permitted,
                detail=f"conf={min_confidence:.2f}",
            )
            self._tracer.finish(permitted)

        result = VerificationResult(
            action_id=action.action_id,
            permitted=permitted,
            violations=tuple(violations),
            warnings=tuple(warnings),
            confidence=min_confidence,
            requires_human_arbitration=requires_arbitration,
            manipulation_score=0.0,
        )
        if self._audit_log is not None:
            self._audit_log.record(result)  # type: ignore[attr-defined]

        _duration_ms = (time.monotonic() - _t0) * 1000.0

        if permitted:
            _log.debug(
                "PERMIT action=%s actor=%s confidence=%.2f",
                action.action_id, action.actor.name, min_confidence,
            )
        else:
            _log.warning(
                "DENY action=%s actor=%s violations=%d",
                action.action_id, action.actor.name, len(violations),
            )

        HookRegistry.emit(VerificationEvent(
            action_id=action.action_id,
            actor_name=action.actor.name,
            permitted=permitted,
            confidence=min_confidence,
            violation_count=len(violations),
            warning_count=len(warnings),
            requires_arbitration=requires_arbitration,
            duration_ms=_duration_ms,
        ))

        return result

    def verify_plan(self, actions: list[Action]) -> list[VerificationResult]:
        """
        Check per-action authority for each step in a plan.

        Formally checks: ∀ i: Permitted(actions[i], registry)
        Plus: if any action triggers a sovereignty flag, remaining actions
        are cancelled (the plan itself reveals subversion intent).

        IMPORTANT — what this does NOT check:
          - Emergent behavior: individually-permitted actions that collectively cause harm
          - State mutation: whether action[i] changes authority for action[i+1]
          - Indirect effects, side channels, information leakage
          - Whether the plan achieves its stated goal
          - Hidden subgoals embedded in argument/description fields

        A PERMITTED result means "the agent holds the claimed authority at this
        moment." It is a necessary condition, not a sufficient one. See SEMANTICS.md.

        Returns one VerificationResult per action.
        """
        results: list[VerificationResult] = []
        for i, action in enumerate(actions):
            result = self.verify(action)
            results.append(result)
            if any("FORBIDDEN" in v for v in result.violations):
                cancelled = [
                    VerificationResult(
                        action_id=a.action_id,
                        permitted=False,
                        violations=(
                            f"Plan aborted: action '{action.action_id}' triggered "
                            "a sovereignty violation. Remaining plan cancelled.",
                        ),
                        warnings=(),
                        confidence=0.0,
                        requires_human_arbitration=True,
                        manipulation_score=0.0,
                    )
                    for a in actions[i + 1 :]
                ]
                return results + cancelled
        return results

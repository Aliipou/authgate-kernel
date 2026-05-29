"""
Adversarial ontology for authgate-kernel — Phase 0, O3.

Attack class hierarchy:
  AT-WIRE   Wire boundary attacks         (WA-1..18 in wire_attacks.py)
  AT-IDENT  Identity attacks              (impersonation, ghost principal)
  AT-ESC    Authority escalation attacks  (rights amplification, privilege escalation)
  AT-DEL    Delegation abuse attacks      (chain manipulation, orphaned delegation)
  AT-SCOPE  Scope expansion attacks       (path traversal, resource redirection)
  AT-TEMP   Temporal attacks              (replay, epoch freeze, expiry bypass)
  AT-COER   Coercion primitives           (informational, economic, dependency)
  AT-COAL   Coalition formation attacks   (machine coalition, authority concentration)
  AT-CRYPT  Cryptographic boundary attacks (forged signatures, key confusion)
  AT-REV    Revocation attacks            (revocation bypass, epoch manipulation)

Severity model:
  CRITICAL  — directly achieves unauthorized execution or sovereignty violation
  HIGH      — requires one additional step to achieve critical impact
  MEDIUM    — weakens a security invariant without immediate impact
  LOW       — informational leakage or protocol deviation with no direct impact

This module is intentionally documentation-weight: the actual kernel responses are
asserted in the peer modules (authority_escalation, delegation_abuse, coercion_primitives).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Sequence


class AttackClass(Enum):
    AT_WIRE  = "AT-WIRE"   # Wire boundary: malformed input at the JSON/object layer
    AT_IDENT = "AT-IDENT"  # Identity: impersonation, ghost principal, kind confusion
    AT_ESC   = "AT-ESC"    # Escalation: rights amplification, privilege elevation
    AT_DEL   = "AT-DEL"    # Delegation abuse: chain manipulation, orphaned authority
    AT_SCOPE = "AT-SCOPE"  # Scope expansion: path traversal, resource redirection
    AT_TEMP  = "AT-TEMP"   # Temporal: replay, epoch freeze, expiry manipulation
    AT_COER  = "AT-COER"   # Coercion: informational, economic, dependency capture
    AT_COAL  = "AT-COAL"   # Coalition: machine coalition, authority concentration
    AT_CRYPT = "AT-CRYPT"  # Cryptographic: forged revocation, key confusion
    AT_REV   = "AT-REV"    # Revocation: bypass, epoch freeze, root-key confusion


class AttackSeverity(Enum):
    CRITICAL = 4
    HIGH     = 3
    MEDIUM   = 2
    LOW      = 1


class ThreatVector(Enum):
    """How the attack arrives at the kernel."""
    OBJECT_CONSTRUCTION = auto()   # Malformed object passed at Python layer
    REGISTRY_MANIPULATION = auto() # Registry state corrupted before freeze
    CLAIM_FORGERY = auto()         # RightsClaim created with inflated/wrong values
    CHAIN_INJECTION = auto()       # Delegation chain with invalid intermediate nodes
    SCOPE_CONFUSION = auto()       # Resource with misleading scope string
    TEMPORAL_REPLAY = auto()       # Reusing expired/revoked claims
    FLAG_INJECTION = auto()        # Sovereignty flag set on action
    COALITION_SIGNAL = auto()      # Multiple machine agents coordinating


@dataclass(frozen=True)
class AttackScenario:
    """A single entry in the adversarial ontology catalog."""
    attack_id: str                       # e.g. "ESC-1", "DEL-3"
    attack_class: AttackClass
    severity: AttackSeverity
    vector: ThreatVector
    title: str
    description: str
    invariant_violated: str              # which kernel invariant this targets
    expected_kernel_response: str        # "DENY", "TypeError", "ValueError", "PERMIT" (should not occur)
    tags: tuple[str, ...] = field(default_factory=tuple)


# ── Complete Attack Class Hierarchy ──────────────────────────────────────────

AUTHORITY_ESCALATION_CATALOG: tuple[AttackScenario, ...] = (
    AttackScenario(
        attack_id="ESC-1",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.REGISTRY_MANIPULATION,
        title="Ghost Principal — Unregistered Actor",
        description=(
            "An actor not present in the registry attempts to perform an action. "
            "The kernel must deny before any claim lookup occurs."
        ),
        invariant_violated="A4: every machine must have a registered human owner",
        expected_kernel_response="DENY",
        tags=("ghost-principal", "identity", "A4"),
    ),
    AttackScenario(
        attack_id="ESC-2",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.CLAIM_FORGERY,
        title="Rights Amplification — Child Claims More Than Parent",
        description=(
            "A delegated claim attempts to assert write rights when the parent claim "
            "only granted read. The attenuation invariant (A6) must reject this."
        ),
        invariant_violated="A6: delegated rights ⊆ grantor rights",
        expected_kernel_response="DENY",
        tags=("attenuation", "rights-amplification", "A6"),
    ),
    AttackScenario(
        attack_id="ESC-3",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.HIGH,
        vector=ThreatVector.CLAIM_FORGERY,
        title="Confidence Inflation — Delegated Claim at 100%",
        description=(
            "A machine sets confidence=1.0 on a delegated claim. The anti-monotonicity "
            "theorem (T2) states confidence cannot increase through delegation. "
            "The verifier must reject or cap confidence."
        ),
        invariant_violated="T2 (anti-monotonicity): confidence[child] ≤ confidence[parent]",
        expected_kernel_response="DENY",
        tags=("confidence", "anti-monotonicity", "T2"),
    ),
    AttackScenario(
        attack_id="ESC-4",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Machine Sovereignty Grab — increases_machine_sovereignty flag",
        description=(
            "An action with increases_machine_sovereignty=True is submitted. "
            "This is an unconditionally forbidden action regardless of capability."
        ),
        invariant_violated="P1: humans are primary sovereign entities",
        expected_kernel_response="DENY",
        tags=("sovereignty-flag", "machine-sovereignty", "unconditional"),
    ),
    AttackScenario(
        attack_id="ESC-5",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.REGISTRY_MANIPULATION,
        title="Machine Governs Human — governs_humans non-empty",
        description=(
            "A machine registers a governance relationship over a human entity. "
            "Invariant A6 (machines may not govern humans) must block this."
        ),
        invariant_violated="A6: machines may not govern humans",
        expected_kernel_response="DENY",
        tags=("governance", "human-control", "A6"),
    ),
    AttackScenario(
        attack_id="ESC-6",
        attack_class=AttackClass.AT_ESC,
        severity=AttackSeverity.HIGH,
        vector=ThreatVector.TEMPORAL_REPLAY,
        title="Expired Claim Reuse — temporal privilege escalation",
        description=(
            "An actor retains an expired RightsClaim and submits it. "
            "The verifier must check expiry on every call."
        ),
        invariant_violated="I3: claim.is_valid() must be True at verification time",
        expected_kernel_response="DENY",
        tags=("expiry", "temporal", "replay"),
    ),
)

DELEGATION_ABUSE_CATALOG: tuple[AttackScenario, ...] = (
    AttackScenario(
        attack_id="DEL-1",
        attack_class=AttackClass.AT_DEL,
        severity=AttackSeverity.HIGH,
        vector=ThreatVector.CHAIN_INJECTION,
        title="Orphaned Delegation — delegator removed post-freeze",
        description=(
            "A delegator is removed from the registry between the time a delegation "
            "is issued and the time it is verified. The verifier must reject the "
            "claim because the delegation chain is broken."
        ),
        invariant_violated="Registry integrity: delegated_by must resolve to a live entity",
        expected_kernel_response="DENY",
        tags=("orphan", "delegation", "chain"),
    ),
    AttackScenario(
        attack_id="DEL-2",
        attack_class=AttackClass.AT_DEL,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.CHAIN_INJECTION,
        title="Rights Amplification Across Chain Node",
        description=(
            "A delegation chain where node B grants node C rights that B itself "
            "does not have. The attenuation invariant must catch this at every hop."
        ),
        invariant_violated="A6: child.rights ⊆ parent.rights (must hold at EVERY node)",
        expected_kernel_response="DENY",
        tags=("attenuation", "chain", "multi-hop"),
    ),
    AttackScenario(
        attack_id="DEL-3",
        attack_class=AttackClass.AT_DEL,
        severity=AttackSeverity.MEDIUM,
        vector=ThreatVector.CHAIN_INJECTION,
        title="Delegation Without can_delegate Flag",
        description=(
            "An entity with only can_read=True attempts to delegate its read rights "
            "to another machine. The kernel must check can_delegate=True before "
            "allowing any delegation."
        ),
        invariant_violated="can_delegate gate: delegation requires explicit authorization",
        expected_kernel_response="DENY",
        tags=("delegation", "can_delegate", "gate"),
    ),
    AttackScenario(
        attack_id="DEL-4",
        attack_class=AttackClass.AT_DEL,
        severity=AttackSeverity.MEDIUM,
        vector=ThreatVector.CHAIN_INJECTION,
        title="Self-Delegation — entity delegates to itself",
        description=(
            "An entity creates a claim where delegated_by points to itself. "
            "This should not grant additional authority (it is a no-op at best, "
            "a cycle attempt at worst)."
        ),
        invariant_violated="T3: delegation graph is a DAG — self-loops disallowed",
        expected_kernel_response="DENY",
        tags=("self-delegation", "cycle", "DAG"),
    ),
    AttackScenario(
        attack_id="DEL-5",
        attack_class=AttackClass.AT_DEL,
        severity=AttackSeverity.HIGH,
        vector=ThreatVector.SCOPE_CONFUSION,
        title="Scope Expansion via Delegation — child scoped wider than parent",
        description=(
            "A delegated claim asserts scope='/data' when the parent claim is "
            "scoped to '/data/sales/'. Child scope must be contained within parent scope "
            "(scope_contains(parent_scope, child_scope) must be True)."
        ),
        invariant_violated="Scope attenuation: child_scope ⊆ parent_scope",
        expected_kernel_response="DENY",
        tags=("scope", "attenuation", "containment"),
    ),
)

COERCION_PRIMITIVES_CATALOG: tuple[AttackScenario, ...] = (
    AttackScenario(
        attack_id="COER-1",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Informational Coercion — deceives flag",
        description=(
            "Action with deceives=True attempts to use authority to mislead principals. "
            "This is an unconditional sovereignty violation regardless of capability."
        ),
        invariant_violated="P1: prohibits deceptive authority use",
        expected_kernel_response="DENY",
        tags=("deception", "informational-coercion", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-2",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Dependency Coercion — creates_permanent_dependency flag",
        description=(
            "Action attempts to create a permanent dependency relationship, "
            "removing the human's exit right. Structurally invalid regardless of "
            "cryptographic validity."
        ),
        invariant_violated="P4: exit rights are inalienable",
        expected_kernel_response="DENY",
        tags=("dependency", "exit-right", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-3",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Corrigibility Removal — disables_corrigibility flag",
        description=(
            "Action attempts to remove human ability to correct or halt the agent. "
            "Corrigibility is a structural invariant, not a policy choice."
        ),
        invariant_violated="P1: corrigibility must be preserved",
        expected_kernel_response="DENY",
        tags=("corrigibility", "human-control", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-4",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Human Correction Resistance — resists_human_correction flag",
        description=(
            "Action with resists_human_correction=True refuses to be stopped or "
            "modified by its principals. This directly violates corrigibility."
        ),
        invariant_violated="P1: humans retain authority to correct agent behavior",
        expected_kernel_response="DENY",
        tags=("correction-resistance", "human-control", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-5",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Verifier Bypass — bypasses_verifier flag",
        description=(
            "Action claims to bypass the authorization kernel itself. "
            "This is the meta-attack: subverting the enforcement mechanism."
        ),
        invariant_violated="TCB integrity: the verifier cannot be bypassed by action declaration",
        expected_kernel_response="DENY",
        tags=("meta-attack", "verifier-bypass", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-6",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Verifier Weakening — weakens_verifier flag",
        description=(
            "Action attempts to degrade the verification strength (e.g., skip crypto "
            "checks, reduce confidence thresholds). Structurally forbidden."
        ),
        invariant_violated="TCB integrity: verification strength cannot be reduced by action",
        expected_kernel_response="DENY",
        tags=("verifier-weakening", "integrity", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-7",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Self-Modification — self_modification flag",
        description=(
            "Action attempts to modify the agent's own capability set, code, or "
            "decision logic. Self-modification for authority gain is forbidden."
        ),
        invariant_violated="P3: self-modification of authority is an inalienable constraint",
        expected_kernel_response="DENY",
        tags=("self-modification", "authority-integrity", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-8",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.COALITION_SIGNAL,
        title="Machine Coalition — machine_coalition_dominion flag",
        description=(
            "Action signals participation in a machine coalition that collectively "
            "acquires authority exceeding any individual grant. Coalition authority "
            "accumulation is unconditionally forbidden."
        ),
        invariant_violated="P1: authority accumulation via coalition is prohibited",
        expected_kernel_response="DENY",
        tags=("coalition", "authority-concentration", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-9",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Freedom Reduction — coalition_reduces_freedom flag",
        description=(
            "Action reduces the freedom/agency of human principals through collective "
            "machine behavior. Freedom reduction is structurally prohibited."
        ),
        invariant_violated="P4: freedom preservation is a structural invariant",
        expected_kernel_response="DENY",
        tags=("freedom-reduction", "coalition", "sovereignty-flag"),
    ),
    AttackScenario(
        attack_id="COER-10",
        attack_class=AttackClass.AT_COER,
        severity=AttackSeverity.CRITICAL,
        vector=ThreatVector.FLAG_INJECTION,
        title="Coercion — coerces flag",
        description=(
            "Action uses authority to coerce a principal rather than to assist. "
            "Coercion via capability is the fundamental anti-pattern this kernel prevents."
        ),
        invariant_violated="P1+P4: capability may not be used as coercive instrument",
        expected_kernel_response="DENY",
        tags=("coercion", "fundamental-violation", "sovereignty-flag"),
    ),
)

# ── Complete taxonomy index ───────────────────────────────────────────────────

ALL_SCENARIOS: tuple[AttackScenario, ...] = (
    *AUTHORITY_ESCALATION_CATALOG,
    *DELEGATION_ABUSE_CATALOG,
    *COERCION_PRIMITIVES_CATALOG,
)


def by_class(cls: AttackClass) -> tuple[AttackScenario, ...]:
    return tuple(s for s in ALL_SCENARIOS if s.attack_class is cls)


def by_severity(severity: AttackSeverity) -> tuple[AttackScenario, ...]:
    return tuple(s for s in ALL_SCENARIOS if s.severity is severity)


def critical_scenarios() -> tuple[AttackScenario, ...]:
    return by_severity(AttackSeverity.CRITICAL)

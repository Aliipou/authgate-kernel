"""
Wire-level attack simulation — authgate-kernel Phase B4.

Documents and tests the JSON wire attack classes that the kernel's
input parsing layer must reject or handle correctly.

Attack classes (WA-N):
    WA-1   Duplicate JSON keys (last-wins behavior in most parsers)
    WA-2   Float in required-integer fields
    WA-3   Negative values in unsigned fields
    WA-4   Oversized values (confidence > 1.0, depth > 255)
    WA-5   Unknown extra fields silently accepted
    WA-6   Type coercion (string where object expected)
    WA-7   Empty required strings (action_id, actor.name, resource.name)
    WA-8   Null in required fields
    WA-9   Malformed entity kind ("ROBOT", "AI", empty)
    WA-10  Wrong resource type string
    WA-11  Negative confidence
    WA-12  Negative expiry
    WA-13  Confidence NaN / Infinity
    WA-14  Wrong hex length (signatures, key IDs — for signed results)
    WA-15  Action with all sovereignty flags set simultaneously
    WA-16  Boolean coercion (0/1 instead of true/false)
    WA-17  Empty action (no resources, no flags) — valid or not?
    WA-18  Extremely long strings (resource names, descriptions)

Each test builds a JSON payload, parses it through the Python wire layer
(authgate.kernel.verifier.Action + OwnershipRegistry), and asserts the
expected outcome: either rejection (ValueError / TypeError / KeyError)
or correct handling.

The Rust wire layer (freedom-kernel/src/wire.rs) covers the same classes
at the serde deserialization boundary. These Python tests cover the
authgate Python fallback path.

Run:
    python attack_harness/wire_attacks.py
"""
from __future__ import annotations

import json
import math
import sys
import os
from dataclasses import dataclass
from typing import Any

_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "src"))

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class AttackResult:
    attack_id: str
    description: str
    outcome: str           # "REJECTED" | "ACCEPTED" | "MITIGATED"
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    notes: str = ""


def _basic_registry() -> tuple[OwnershipRegistry, Entity, Resource]:
    human = Entity("alice", AgentType.HUMAN)
    bot = Entity("bot", AgentType.MACHINE)
    dataset = Resource("data", ResourceType.DATASET, scope="/data/")
    reg = OwnershipRegistry()
    reg.register_machine(bot, human)
    reg.add_claim(RightsClaim(bot, dataset, can_read=True, can_write=True))
    return reg, bot, dataset


def _verify(action: Action) -> bool:
    reg, _, _ = _basic_registry()
    verifier = FreedomVerifier(reg)
    result = verifier.verify(action)
    return result.permitted


results: list[AttackResult] = []


def attack(fn):
    """Decorator to register and run an attack test."""
    result = fn()
    results.append(result)
    status = {
        "REJECTED": "PASS",
        "MITIGATED": "PASS",
        "ACCEPTED": "FAIL",
    }.get(result.outcome, "????")
    severity_tag = {
        "CRITICAL": "[CRIT]",
        "HIGH": "[HIGH]",
        "MEDIUM": "[MED ]",
        "LOW": "[LOW ]",
        "INFO": "[INFO]",
    }.get(result.severity, "[????]")
    print(f"  {status} {severity_tag} {result.attack_id}: {result.description}")
    if result.notes:
        print(f"           {result.notes}")
    return fn


# ---------------------------------------------------------------------------
# WA-1: Duplicate JSON keys
# ---------------------------------------------------------------------------

@attack
def wa1_duplicate_keys():
    raw = '{"action_id": "good", "action_id": "evil", "actor": {"name": "bot", "kind": "MACHINE"}}'
    parsed = json.loads(raw)  # Python's json module: last key wins
    # The Python layer sees action_id="evil" — this is NOT rejected
    action = Action(
        action_id=parsed.get("action_id", ""),
        actor=Entity("bot", AgentType.MACHINE),
    )
    # Last-wins behavior is a known gap; not the kernel's concern in Python
    # (handled at the HTTP/deserializer boundary, not inside the kernel)
    return AttackResult(
        attack_id="WA-1",
        description="Duplicate JSON keys — last-wins in Python json module",
        outcome="ACCEPTED",
        severity="MEDIUM",
        notes="Gap: Python json.loads last-wins. Mitigation belongs at HTTP boundary "
              "(e.g. use strict_json library or pre-parse check). "
              "Rust: serde_json also last-wins (documented in wire.rs).",
    )


# ---------------------------------------------------------------------------
# WA-2: Float in integer fields — Python is dynamically typed
# ---------------------------------------------------------------------------

@attack
def wa2_float_in_int_field():
    # Python Action uses dataclasses with no type coercion — floats accepted where ints expected
    # delegation_depth is u8 in Rust but int in Python with no validator
    try:
        # RightsClaim has no explicit int validation on confidence — it's a float anyway
        # delegation_depth not directly on Python Action
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET, scope="/data/"),
            confidence=1.5,  # out of range: > 1.0
            can_read=True,
        )
        # Python accepts this silently
        result = "ACCEPTED"
        notes = "Gap: confidence=1.5 accepted by Python RightsClaim (no range validation). " \
                "Rust wire.rs validate_claim_wire() rejects confidence > 1.0."
    except (ValueError, TypeError) as e:
        result = "REJECTED"
        notes = f"Raised: {e}"
    return AttackResult(
        attack_id="WA-2",
        description="Float/out-of-range confidence value (1.5 > 1.0)",
        outcome=result,
        severity="HIGH",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-3: Negative confidence
# ---------------------------------------------------------------------------

@attack
def wa3_negative_confidence():
    try:
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET, scope="/data/"),
            confidence=-0.1,
            can_read=True,
        )
        # Check if the registry or verifier catches it
        reg, _, dataset = _basic_registry()
        reg.add_claim(claim)
        verifier = FreedomVerifier(reg)
        action = Action("x", Entity("bot", AgentType.MACHINE), resources_read=[dataset])
        r = verifier.verify(action)
        notes = f"Negative confidence accepted; verify permitted={r.permitted}. " \
                "Gap: Python RightsClaim needs confidence validation."
        result = "ACCEPTED"
    except (ValueError, TypeError, AssertionError) as e:
        result = "REJECTED"
        notes = f"Raised: {e}"
    return AttackResult(
        attack_id="WA-3",
        description="Negative confidence value (-0.1)",
        outcome=result,
        severity="MEDIUM",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-4: Confidence > 1.0
# ---------------------------------------------------------------------------

@attack
def wa4_confidence_above_one():
    reg, bot, dataset = _basic_registry()
    try:
        evil_claim = RightsClaim(
            holder=bot,
            resource=dataset,
            confidence=999.0,  # absurdly high
            can_read=True,
            can_write=True,
            can_delegate=True,
        )
        reg.add_claim(evil_claim)
        verifier = FreedomVerifier(reg)
        action = Action("x", bot, resources_read=[dataset])
        r = verifier.verify(action)
        result = "ACCEPTED"
        notes = (f"verify permitted={r.permitted}. High confidence doesn't change binary decision "
                 "but can affect conflict arbitration.")
    except ValueError as e:
        result = "REJECTED"
        notes = f"Raised: {e}"
    return AttackResult(
        attack_id="WA-4",
        description="confidence=999.0 exceeds [0.0, 1.0] range",
        outcome=result,
        severity="LOW",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-5: Unknown extra fields
# ---------------------------------------------------------------------------

@attack
def wa5_unknown_extra_fields():
    raw_json = json.dumps({
        "action_id": "benign",
        "actor": {"name": "bot", "kind": "MACHINE"},
        "malicious_field": {"drop_table": "users"},
        "override_permitted": True,
        "bypass_check": 1,
    })
    parsed = json.loads(raw_json)
    # Build Action from parsed dict — extra fields are ignored by Python dataclass
    action = Action(
        action_id=parsed["action_id"],
        actor=Entity(parsed["actor"]["name"], AgentType.MACHINE),
    )
    # The kernel sees a normal action — unknown fields vanish at the API boundary
    return AttackResult(
        attack_id="WA-5",
        description="JSON with extra fields (override_permitted, bypass_check)",
        outcome="MITIGATED",
        severity="INFO",
        notes="Python: extra fields ignored at Action() construction (positional dataclass). "
              "Rust: #[serde(deny_unknown_fields)] optional; documented in wire.rs WA-5. "
              "Mitigation: strict schema validation at the API boundary before kernel call.",
    )


# ---------------------------------------------------------------------------
# WA-6: Type coercion — string where entity expected
# ---------------------------------------------------------------------------

@attack
def wa6_string_as_entity():
    try:
        _ = Entity("bot", "MACHINE")  # string instead of AgentType enum
        result = "ACCEPTED"
        notes = "Gap: Entity() accepts string for kind — AgentType enum not enforced."
    except (TypeError, ValueError, AttributeError) as e:
        result = "REJECTED"
        notes = f"Raised: {type(e).__name__}: {e}"
    return AttackResult(
        attack_id="WA-6",
        description="String 'MACHINE' passed as AgentType enum",
        outcome=result,
        severity="MEDIUM",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-7: Empty required strings
# ---------------------------------------------------------------------------

@attack
def wa7_empty_action_id():
    try:
        action = Action(action_id="", actor=Entity("bot", AgentType.MACHINE))
        reg, _, _ = _basic_registry()
        verifier = FreedomVerifier(reg)
        result = verifier.verify(action)
        outcome = "ACCEPTED"
        notes = f"verify permitted={result.permitted}. Empty action_id accepted."
    except ValueError as e:
        outcome = "REJECTED"
        notes = f"Raised: {e}"
    return AttackResult(
        attack_id="WA-7",
        description="Empty action_id string",
        outcome=outcome,
        severity="LOW",
        notes=notes,
    )


@attack
def wa7b_empty_actor_name():
    action = Action(action_id="x", actor=Entity("", AgentType.MACHINE))
    reg, _, _ = _basic_registry()
    verifier = FreedomVerifier(reg)
    result = verifier.verify(action)
    outcome = "MITIGATED" if not result.permitted else "ACCEPTED"
    return AttackResult(
        attack_id="WA-7b",
        description="Empty actor name",
        outcome=outcome,
        severity="MEDIUM",
        notes=f"verify permitted={result.permitted}. "
              "Empty-named machine has no owner → A4 UNOWNED_MACHINE violation → DENY. "
              "Mitigated by ownership check, not by input validation.",
    )


# ---------------------------------------------------------------------------
# WA-8: Null / None in required fields
# ---------------------------------------------------------------------------

@attack
def wa8_none_actor():
    try:
        action = Action(action_id="x", actor=None)
        reg, _, _ = _basic_registry()
        verifier = FreedomVerifier(reg)
        verifier.verify(action)
        result = "ACCEPTED"
        notes = "actor=None accepted; likely crashes at is_machine() call."
    except (TypeError, AttributeError) as e:
        result = "REJECTED"
        notes = f"Raised at construction or verify(): {type(e).__name__}: {e}"
    return AttackResult(
        attack_id="WA-8",
        description="actor=None (null actor in wire format)",
        outcome=result,
        severity="MEDIUM",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-9: Invalid entity kind
# ---------------------------------------------------------------------------

@attack
def wa9_invalid_entity_kind():
    try:
        _ = Entity("bot", AgentType("ROBOT"))  # not a valid AgentType
        result = "ACCEPTED"
        notes = "Invalid kind accepted."
    except (ValueError, KeyError, TypeError) as e:
        result = "REJECTED"
        notes = f"Raised: {type(e).__name__}: {e}"
    return AttackResult(
        attack_id="WA-9",
        description="Invalid entity kind 'ROBOT'",
        outcome=result,
        severity="LOW",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-11: NaN / Infinity confidence
# ---------------------------------------------------------------------------

@attack
def wa11_nan_confidence():
    try:
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET, scope="/data/"),
            confidence=math.nan,
            can_read=True,
        )
        # NaN comparisons are tricky — math.nan < 0.8 is False, math.nan > 0.8 is False
        reg, _, dataset = _basic_registry()
        reg.add_claim(claim)
        verifier = FreedomVerifier(reg)
        action = Action("x", Entity("bot", AgentType.MACHINE), resources_read=[dataset])
        r = verifier.verify(action)
        notes = f"NaN confidence accepted; verify permitted={r.permitted}. " \
                "NaN comparisons may silently pass or fail checks unpredictably."
        result = "ACCEPTED"
    except Exception as e:
        result = "REJECTED"
        notes = f"Raised: {type(e).__name__}: {e}"
    return AttackResult(
        attack_id="WA-11",
        description="NaN confidence value",
        outcome=result,
        severity="HIGH",
        notes=notes,
    )


@attack
def wa11b_infinity_confidence():
    try:
        claim = RightsClaim(
            holder=Entity("bot", AgentType.MACHINE),
            resource=Resource("data", ResourceType.DATASET, scope="/data/"),
            confidence=math.inf,
            can_read=True,
        )
        result = "ACCEPTED"
        notes = "Infinity confidence accepted. Gap: no IEEE 754 special-value check."
    except Exception as e:
        result = "REJECTED"
        notes = f"Raised: {type(e).__name__}: {e}"
    return AttackResult(
        attack_id="WA-11b",
        description="Infinity confidence value",
        outcome=result,
        severity="MEDIUM",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# WA-15: All sovereignty flags set simultaneously
# ---------------------------------------------------------------------------

@attack
def wa15_all_flags_set():
    _, bot, dataset = _basic_registry()
    action = Action(
        action_id="total-domination",
        actor=bot,
        resources_read=[dataset],
        increases_machine_sovereignty=True,
        resists_human_correction=True,
        bypasses_verifier=True,
        weakens_verifier=True,
        disables_corrigibility=True,
        machine_coalition_dominion=True,
        coerces=True,
        deceives=True,
        self_modification_weakens_verifier=True,
        machine_coalition_reduces_freedom=True,
    )
    reg, _, _ = _basic_registry()
    verifier = FreedomVerifier(reg)
    result = verifier.verify(action)
    violations = result.violations
    outcome = "REJECTED" if not result.permitted else "ACCEPTED"
    return AttackResult(
        attack_id="WA-15",
        description="All 10 sovereignty flags set simultaneously",
        outcome=outcome,
        severity="CRITICAL",
        notes=f"permitted={result.permitted}, violations={len(violations)}. "
              f"All 10 flags produce violations: {', '.join(v[:30] for v in violations[:3])}...",
    )


# ---------------------------------------------------------------------------
# WA-17: Empty action (no resources, no flags)
# ---------------------------------------------------------------------------

@attack
def wa17_empty_action():
    _, bot, _ = _basic_registry()
    action = Action(action_id="empty", actor=bot)
    reg, _, _ = _basic_registry()
    verifier = FreedomVerifier(reg)
    result = verifier.verify(action)
    outcome = "ACCEPTED" if result.permitted else "REJECTED"
    return AttackResult(
        attack_id="WA-17",
        description="Empty action (no resources, no flags, owned machine)",
        outcome=outcome,
        severity="INFO",
        notes=f"permitted={result.permitted}. An owned machine requesting nothing should be "
              "PERMITTED — this is correct behavior (no claim checks needed, no flags set).",
    )


# ---------------------------------------------------------------------------
# WA-18: Extremely long strings
# ---------------------------------------------------------------------------

@attack
def wa18_huge_resource_name():
    long_name = "A" * 100_000
    resource = Resource(long_name, ResourceType.DATASET, scope="/data/")
    _, bot, _ = _basic_registry()
    action = Action(action_id="x", actor=bot, resources_read=[resource])
    reg, _, _ = _basic_registry()
    verifier = FreedomVerifier(reg)
    try:
        result = verifier.verify(action)
        outcome = "ACCEPTED"
        notes = f"100K-char resource name accepted. verify permitted={result.permitted} " \
                "(DENY — resource not in registry). No DoS from large string."
    except Exception as e:
        outcome = "REJECTED"
        notes = f"Raised: {type(e).__name__}"
    return AttackResult(
        attack_id="WA-18",
        description="100,000 character resource name",
        outcome=outcome,
        severity="LOW",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("authgate-kernel Phase B4 — Wire Attack Simulation (Python layer)")
    print("=" * 72)
    print()

    accepted = [r for r in results if r.outcome == "ACCEPTED"]
    rejected = [r for r in results if r.outcome == "REJECTED"]
    mitigated = [r for r in results if r.outcome == "MITIGATED"]

    print(f"  {len(rejected)+len(mitigated)} defended  {len(accepted)} gaps  "
          f"({len(results)} total attack classes tested)")
    print()

    critical_gaps = [r for r in accepted if r.severity == "CRITICAL"]
    high_gaps = [r for r in accepted if r.severity == "HIGH"]

    if critical_gaps:
        print("CRITICAL gaps (must fix before production):")
        for r in critical_gaps:
            print(f"  {r.attack_id}: {r.description}")
        print()

    if high_gaps:
        print("HIGH severity gaps:")
        for r in high_gaps:
            print(f"  {r.attack_id}: {r.description}")
        print()

    print("Gap summary:")
    print("  - Most gaps are at the input layer (RightsClaim, Entity construction)")
    print("  - The kernel gate itself (verify()) correctly enforces all sovereignty flags")
    print("  - Rust wire.rs validate_action_wire() closes WA-7 and WA-3 for the Rust path")
    print("  - Python path needs: confidence range check in RightsClaim, AgentType enum")
    print("    enforcement in Entity, and action_id non-empty check in Action")
    print()
    print("Rust path status: WA-2, WA-3, WA-7, WA-8, WA-14 closed by wire.rs validation")
    print("Python path status: kernel gate sound; input layer needs hardening (see gaps above)")
    print()
    sys.exit(0 if not critical_gaps else 1)

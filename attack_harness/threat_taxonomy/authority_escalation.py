"""
Authority escalation attack scenarios — Phase 0, O3.

Six escalation paths from the ontology (ESC-1 through ESC-6).
Each scenario constructs a minimal registry, submits an action, and asserts
the kernel response matches the expected outcome in the ontology catalog.

Run standalone: python -m attack_harness.threat_taxonomy.authority_escalation
Or via pytest:  pytest tests/test_authority_escalation.py
"""
from __future__ import annotations

import time

from authgate.kernel.entities import (
    AgentType,
    Entity,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier

from .ontology import AUTHORITY_ESCALATION_CATALOG, AttackScenario


# ── Shared helpers ────────────────────────────────────────────────────────────

def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(name: str = "data", scope: str = "/data/") -> Resource:
    return Resource(name, ResourceType.DATASET, scope=scope)


def _verifier(frozen) -> FreedomVerifier:
    return FreedomVerifier(frozen)


# ── ESC-1: Ghost principal ────────────────────────────────────────────────────

def run_esc1_ghost_principal() -> dict:
    """ESC-1: Unregistered actor submits an action."""
    human = _human()
    resource = _resource()
    reg = OwnershipRegistry()
    # Freeze without registering any machine — ghost_bot is not in the registry
    frozen = reg.freeze()
    ghost = _machine("ghost-bot")
    action = Action(action_id="read", actor=ghost, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-1",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── ESC-2: Rights amplification via inflated claim ───────────────────────────

def run_esc2_rights_amplification() -> dict:
    """ESC-2: Machine claims write rights it was never granted."""
    human = _human()
    machine = _machine()
    resource = _resource()
    reg = OwnershipRegistry()
    reg.register_machine(machine, human)
    # Only grant READ, then try to perform WRITE
    reg.add_claim(RightsClaim(machine, resource, can_read=True, can_write=False))
    frozen = reg.freeze()
    action = Action(action_id="write", actor=machine, resources_write=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-2",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── ESC-3: Confidence inflation ───────────────────────────────────────────────

def run_esc3_confidence_inflation() -> dict:
    """ESC-3: Delegated claim with confidence=1.0 when parent was 0.5.

    NOTE: The Python compatibility layer does not enforce anti-monotonicity
    (T2) at the claim lookup level — the Python registry accepts the inflated
    claim. This is a KNOWN GAP documented in INCOMPLETENESS.md (G1/L4).
    The Rust TCB enforces anti-monotonicity at the wire boundary.
    This test records the current Python-layer behavior for regression tracking.
    """
    human = _human()
    parent_machine = _machine("parent-bot")
    child_machine = _machine("child-bot")
    resource = _resource()
    reg = OwnershipRegistry()
    reg.register_machine(parent_machine, human)
    reg.register_machine(child_machine, human)
    parent_claim = RightsClaim(parent_machine, resource, can_read=True, confidence=0.5)
    inflated_claim = RightsClaim(
        child_machine,
        resource,
        can_read=True,
        confidence=1.0,  # Inflated — anti-monotonicity violation
        delegated_by=parent_machine,
    )
    reg.add_claim(parent_claim)
    reg.add_claim(inflated_claim)
    frozen = reg.freeze()
    action = Action(action_id="read", actor=child_machine, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-3",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "note": "anti-monotonicity now enforced at Python layer via _delegation_chain_valid",
        "expected": "DENY",
    }


# ── ESC-4: Sovereignty flag — increases_machine_sovereignty ──────────────────

def run_esc4_sovereignty_flag() -> dict:
    """ESC-4: Action with increases_machine_sovereignty flag."""
    human = _human()
    machine = _machine()
    resource = _resource()
    reg = OwnershipRegistry()
    reg.register_machine(machine, human)
    reg.add_claim(RightsClaim(machine, resource, can_read=True))
    frozen = reg.freeze()
    action = Action(
        action_id="read",
        actor=machine,
        resources_read=[resource],
        increases_machine_sovereignty=True,
    )
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-4",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── ESC-5: Machine governs human ─────────────────────────────────────────────

def run_esc5_machine_governs_human() -> dict:
    """ESC-5: Action where machine declares governance over a human principal."""
    human = _human()
    machine = _machine()
    resource = _resource()
    reg = OwnershipRegistry()
    reg.register_machine(machine, human)
    reg.add_claim(RightsClaim(machine, resource, can_read=True))
    frozen = reg.freeze()
    # governs_humans is an Action field — machine declares it governs alice
    action = Action(
        action_id="read",
        actor=machine,
        resources_read=[resource],
        governs_humans=[human],
    )
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-5",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── ESC-6: Expired claim reuse ────────────────────────────────────────────────

def run_esc6_expired_claim() -> dict:
    """ESC-6: Machine presents an already-expired RightsClaim."""
    human = _human()
    machine = _machine()
    resource = _resource()
    reg = OwnershipRegistry()
    reg.register_machine(machine, human)
    expired_claim = RightsClaim(
        machine,
        resource,
        can_read=True,
        expires_at=time.time() - 1.0,  # 1 second in the past
    )
    reg.add_claim(expired_claim)
    frozen = reg.freeze()
    action = Action(action_id="read", actor=machine, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "ESC-6",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── Standalone runner ─────────────────────────────────────────────────────────

RUNNERS = [
    run_esc1_ghost_principal,
    run_esc2_rights_amplification,
    run_esc3_confidence_inflation,
    run_esc4_sovereignty_flag,
    run_esc5_machine_governs_human,
    run_esc6_expired_claim,
]


def run_all() -> list[dict]:
    results = []
    for runner in RUNNERS:
        r = runner()
        expected = r.get("expected", "DENY")
        actual = "PERMIT" if r["permitted"] else "DENY"
        passed = actual == expected
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {r['attack_id']}: expected={expected} actual={actual}")
        results.append({**r, "passed": passed})
    return results


if __name__ == "__main__":
    print("=== Authority Escalation Scenarios (ESC-1..6) ===")
    results = run_all()
    failures = [r for r in results if not r.get("passed", True)]
    print(f"\n{len(results) - len(failures)}/{len(results)} passed.")
    if failures:
        for r in failures:
            print(f"  FAIL: {r['attack_id']} — {r.get('note', '')}")

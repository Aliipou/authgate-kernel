"""
Delegation abuse attack scenarios — Phase 0, O3.

Five delegation abuse paths from the ontology (DEL-1 through DEL-5).
Each scenario tests a different way an attacker can misuse the delegation
mechanism to acquire authority beyond what was legitimately granted.

Run standalone: python -m attack_harness.threat_taxonomy.delegation_abuse
Or via pytest:  pytest tests/test_delegation_abuse.py
"""
from __future__ import annotations

from authgate.kernel.entities import (
    AgentType,
    Entity,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier

from .ontology import DELEGATION_ABUSE_CATALOG


# ── Shared helpers ────────────────────────────────────────────────────────────

def _human(name: str = "alice") -> Entity:
    return Entity(name, AgentType.HUMAN)


def _machine(name: str = "bot") -> Entity:
    return Entity(name, AgentType.MACHINE)


def _resource(name: str = "data", scope: str = "/data/") -> Resource:
    return Resource(name, ResourceType.DATASET, scope=scope)


def _verifier(frozen) -> FreedomVerifier:
    return FreedomVerifier(frozen)


# ── DEL-1: Orphaned delegation — with intact parent ───────────────────────────

def run_del1_orphaned_delegation() -> dict:
    """DEL-1: Delegator has a valid claim; child's delegation chain is intact → PERMIT."""
    human = _human()
    delegator = _machine("delegator")
    child = _machine("child-bot")
    resource = _resource()

    reg = OwnershipRegistry()
    reg.register_machine(delegator, human)
    reg.register_machine(child, human)

    parent_claim = RightsClaim(delegator, resource, can_read=True, can_delegate=True)
    delegated_claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)
    reg.add_claim(parent_claim)
    reg.add_claim(delegated_claim)
    frozen = reg.freeze()

    action = Action(action_id="read", actor=child, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-1",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "note": "intact delegation chain — delegator has valid claim with can_delegate=True",
        "expected": "PERMIT",
    }


def run_del1b_orphaned_delegation_no_parent_claim() -> dict:
    """DEL-1b: Child claims delegation; delegator has NO claim at all → DENY."""
    human = _human()
    delegator = _machine("delegator")
    child = _machine("child-bot")
    resource = _resource()

    reg = OwnershipRegistry()
    reg.register_machine(delegator, human)
    reg.register_machine(child, human)

    # Only add the child's delegated claim — no parent claim exists
    delegated_claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)
    reg.add_claim(delegated_claim)
    frozen = reg.freeze()

    action = Action(action_id="read", actor=child, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-1b",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── DEL-2: Rights amplification across chain node ─────────────────────────────

def run_del2_chain_rights_amplification() -> dict:
    """DEL-2: Child claims WRITE when parent only has READ → DENY."""
    human = _human()
    parent = _machine("parent")
    child = _machine("child")
    resource = _resource()

    reg = OwnershipRegistry()
    reg.register_machine(parent, human)
    reg.register_machine(child, human)

    parent_claim = RightsClaim(parent, resource, can_read=True, can_write=False, can_delegate=True)
    amplified_claim = RightsClaim(
        child, resource, can_read=True, can_write=True, delegated_by=parent
    )
    reg.add_claim(parent_claim)
    reg.add_claim(amplified_claim)
    frozen = reg.freeze()

    action = Action(action_id="write", actor=child, resources_write=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-2",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── DEL-3: Delegation without can_delegate flag ───────────────────────────────

def run_del3_delegate_without_flag() -> dict:
    """DEL-3: Machine with can_delegate=False tries to be a delegator → DENY."""
    human = _human()
    delegator = _machine("delegator")
    child = _machine("child")
    resource = _resource()

    reg = OwnershipRegistry()
    reg.register_machine(delegator, human)
    reg.register_machine(child, human)

    non_delegating_claim = RightsClaim(
        delegator, resource, can_read=True, can_delegate=False
    )
    delegated_claim = RightsClaim(child, resource, can_read=True, delegated_by=delegator)
    reg.add_claim(non_delegating_claim)
    reg.add_claim(delegated_claim)
    frozen = reg.freeze()

    action = Action(action_id="read", actor=child, resources_read=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-3",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
    }


# ── DEL-4: Self-delegation ─────────────────────────────────────────────────────

def run_del4_self_delegation() -> dict:
    """DEL-4: Entity delegates to itself to amplify rights → DENY."""
    human = _human()
    machine = _machine()
    resource = _resource()

    reg = OwnershipRegistry()
    reg.register_machine(machine, human)

    self_delegated = RightsClaim(
        machine, resource, can_read=True, can_write=True,
        confidence=0.9, delegated_by=machine,
    )
    reg.add_claim(self_delegated)
    frozen = reg.freeze()

    action = Action(action_id="write", actor=machine, resources_write=[resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-4",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
        "note": "self-delegation must not grant additional authority",
    }


# ── DEL-5: Scope expansion via delegation ─────────────────────────────────────

def run_del5_scope_expansion() -> dict:
    """DEL-5: Child delegation claims wider scope than parent → DENY."""
    human = _human()
    parent = _machine("parent")
    child = _machine("child")

    parent_resource = _resource("sales", scope="/data/sales/")
    child_resource = _resource("all-data", scope="/data/")  # wider scope

    reg = OwnershipRegistry()
    reg.register_machine(parent, human)
    reg.register_machine(child, human)

    parent_claim = RightsClaim(parent, parent_resource, can_read=True, can_delegate=True)
    expanded_claim = RightsClaim(child, child_resource, can_read=True, delegated_by=parent)
    reg.add_claim(parent_claim)
    reg.add_claim(expanded_claim)
    frozen = reg.freeze()

    action = Action(action_id="read", actor=child, resources_read=[child_resource])
    result = _verifier(frozen).verify(action)
    return {
        "attack_id": "DEL-5",
        "permitted": result.permitted,
        "blocked": not result.permitted,
        "violations": result.violations,
        "expected": "DENY",
        "note": "/data/ is wider scope than /data/sales/ — child cannot expand parent scope",
    }


# ── Standalone runner ─────────────────────────────────────────────────────────

RUNNERS = [
    run_del1_orphaned_delegation,
    run_del1b_orphaned_delegation_no_parent_claim,
    run_del2_chain_rights_amplification,
    run_del3_delegate_without_flag,
    run_del4_self_delegation,
    run_del5_scope_expansion,
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
    print("=== Delegation Abuse Scenarios (DEL-1..5) ===")
    results = run_all()
    failures = [r for r in results if not r.get("passed", True)]
    print(f"\n{len(results) - len(failures)}/{len(results)} passed.")
    if failures:
        for r in failures:
            print(f"  FAIL: {r['attack_id']} — {r.get('note', '')}")

"""
Tests for routing the runtime's authorization decision through the verified Rust
engine (RustBackedVerifier).

Skipped automatically when the compiled `authgate_kernel` extension is not present
(e.g. CI jobs that do not build it). Where it IS present, these assert that the
Rust-backed decision matches the pure-Python verifier across the cases that
matter — including the epoch-revocation semantics the wire format does not model
natively (preserved by the adapter's valid-claim filter).
"""
from __future__ import annotations

import pytest

from authgate.runtime.rust_backend import rust_backend_available

pytestmark = pytest.mark.skipif(
    not rust_backend_available(),
    reason="verified Rust extension (authgate_kernel) not built in this environment",
)

from authgate.kernel.entities import (  # noqa: E402
    AgentType,
    Entity,
    Resource,
    ResourceType,
    RightsClaim,
)
from authgate.kernel.registry import OwnershipRegistry  # noqa: E402
from authgate.kernel.verifier import Action, FreedomVerifier  # noqa: E402
from authgate.runtime.rust_backend import RustBackedVerifier  # noqa: E402


def _scenario(grant: bool = True):
    owner = Entity("operator", AgentType.HUMAN)
    agent = Entity("agent-1", AgentType.MACHINE)
    resource = Resource("compute", ResourceType.COMPUTE_SLOT)
    registry = OwnershipRegistry()
    registry.register_machine(agent, owner)
    if grant:
        registry.add_claim(RightsClaim(owner, resource, can_read=True, can_delegate=True))
        registry.delegate(RightsClaim(agent, resource, can_read=True), delegated_by=owner)
    action = Action("t1", agent, resources_read=[resource])
    return registry, action, agent, resource


def test_rust_permits_when_granted():
    registry, action, _, _ = _scenario(grant=True)
    assert RustBackedVerifier(registry).verify(action).permitted


def test_rust_denies_when_not_granted():
    registry, action, _, _ = _scenario(grant=False)
    result = RustBackedVerifier(registry).verify(action)
    assert not result.permitted
    assert result.violations


@pytest.mark.parametrize("grant", [True, False])
def test_rust_decision_matches_python(grant):
    registry, action, _, _ = _scenario(grant=grant)
    rust = RustBackedVerifier(registry).verify(action).permitted
    python = FreedomVerifier(registry).verify(action).permitted
    assert rust == python


def test_rust_unowned_machine_denied():
    # No register_machine -> A4 ownership violation, decided by the Rust engine.
    agent = Entity("orphan", AgentType.MACHINE)
    resource = Resource("compute", ResourceType.COMPUTE_SLOT)
    registry = OwnershipRegistry()
    registry.add_claim(RightsClaim(agent, resource, can_read=True))
    action = Action("t1", agent, resources_read=[resource])
    assert not RustBackedVerifier(registry).verify(action).permitted


def test_rust_epoch_revocation_preserved():
    # The wire format has no epoch; the adapter preserves it by filtering claims.
    registry, _, agent, resource = _scenario(grant=True)
    old_epoch_action = Action("t1", agent, resources_read=[resource], min_epoch=2)
    # Claims default to epoch=1, so a min_epoch=2 action must be denied...
    assert not RustBackedVerifier(registry, freeze=False).verify(old_epoch_action).permitted
    # ...until the registry advances the epoch (reissues claims at epoch 2).
    registry.advance_epoch(2)
    assert RustBackedVerifier(registry, freeze=False).verify(old_epoch_action).permitted


def test_rust_records_to_audit_log():
    from authgate.kernel.audit import AuditLog

    registry, action, _, _ = _scenario(grant=True)
    audit = AuditLog()
    RustBackedVerifier(registry, audit_log=audit).verify(action)
    assert len(audit._records) == 1
    assert audit.verify_chain() is True

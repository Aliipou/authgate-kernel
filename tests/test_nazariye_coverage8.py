"""
Coverage tests (batch 8) added on the `nazariye-azadi` branch.

Targets the consent algebra (ConsentCapability / ConsentAnnotation), the consent
registry diagnostics, and the policy-verifier delegate branch.
"""
from __future__ import annotations

import time

import pytest

from authgate.kernel import consent as consent_mod
from authgate.kernel.consent import ConsentAnnotation, ConsentCapability
from authgate.kernel.consent_registry import ConsentRegistry
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


def _human(name="Alice"):
    return Entity(name, AgentType.HUMAN)


def _machine(name="Bot"):
    return Entity(name, AgentType.MACHINE)


def _res(name="doc", scope=""):
    return Resource(name, ResourceType.FILE, scope=scope)


# --------------------------------------------------------------------------- #
# consent.py
# --------------------------------------------------------------------------- #

def test_consent_capability_rejects_non_entity_grantor():
    with pytest.raises(TypeError):  # line 85
        ConsentCapability(
            grantor="not-an-entity",  # type: ignore[arg-type]
            grantee=_machine(),
            resource=_res(),
            operations=frozenset({"read"}),
            expires_at=time.time() + 100,
        )


def test_consent_capability_covers_false_when_expired(monkeypatch):
    cap = ConsentCapability(
        grantor=_human(), grantee=_machine(), resource=_res(),
        operations=frozenset({"read"}), expires_at=time.time() + 100,
    )
    # advance the clock past expiry -> is_valid() False -> covers() returns False (line 133)
    future = time.time() + 1000
    monkeypatch.setattr(consent_mod.time, "time", lambda: future)
    assert cap.is_valid() is False
    assert cap.covers("read") is False


def test_consent_annotation_no_requirement_returns_none():
    ann = ConsentAnnotation(claim=None, consent_required=False)
    assert ann.consent_violation_reason() is None  # line 187
    assert ann.is_consent_valid() is True


def test_consent_annotation_scope_mismatch_reason():
    claim = RightsClaim(_human(), _res("doc", scope="other/area"))
    ann = ConsentAnnotation(
        claim=claim,
        consent_required=True,
        consent_given_by=_human(),
        consent_scope="allowed/area",
    )
    reason = ann.consent_violation_reason()  # line 198
    assert reason is not None
    assert "not within" in reason


# --------------------------------------------------------------------------- #
# consent_registry.py
# --------------------------------------------------------------------------- #

def test_consent_registry_check_expired(monkeypatch):
    reg = ConsentRegistry()
    bot = _machine()
    res = _res()
    cap = ConsentCapability(
        grantor=_human(), grantee=bot, resource=res,
        operations=frozenset({"read"}), expires_at=time.time() + 100,
    )
    reg.grant(cap)
    # advance clock so the only candidate is expired -> diagnostic "has expired" (line 133)
    future = time.time() + 1000
    monkeypatch.setattr(consent_mod.time, "time", lambda: future)
    ok, reason = reg.check(bot, res, "read")
    assert ok is False
    assert "expired" in reason


# --------------------------------------------------------------------------- #
# policy.py — PolicyVerifier delegate-deny branch
# --------------------------------------------------------------------------- #

def test_policy_verifier_denies_delegate():
    reg = OwnershipRegistry()
    alice = _human()
    bot = _machine()
    reg.register_machine(bot, alice)
    res = _res("doc", scope="proj")
    reg.add_claim(RightsClaim(bot, res, can_read=True, can_delegate=True))

    kernel = FreedomVerifier(reg)
    policy = Policy(
        name="no-delegate",
        rules=[PolicyRule(effect="deny", operations=["delegate"], resource_scope="proj")],
        default_effect="permit",
    )
    pv = PolicyVerifier(kernel=kernel, policy=policy)
    action = Action("a", bot, resources_delegate=[res])
    result = pv.verify(action)
    assert result.permitted is False
    assert any("POLICY DENIED delegate" in v for v in result.violations)

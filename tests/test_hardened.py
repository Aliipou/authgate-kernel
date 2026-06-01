"""Tests for HardenedVerifier — the trusted-input gate that closes the
red-team findings. Mirrors redteam/test_redteam_regression.py as pytest cases
so the hardened path is covered by `pytest --cov`."""
from __future__ import annotations

import pytest

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.hardened import HardenedVerifier, TrustBoundaryError
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action

H = AgentType.HUMAN
M = AgentType.MACHINE
DB = ResourceType.DATABASE_TABLE
CRED = ResourceType.CREDENTIAL
MW = ResourceType.MODEL_WEIGHTS


def world():
    reg = OwnershipRegistry()
    alice = Entity("alice", H, identity_token="alice-secret")
    bot = Entity("bot", M, identity_token="bot-secret")
    reg.register_machine(bot, alice)
    prod_db = Resource("prod_db", DB, is_public=False)
    reg.add_claim(RightsClaim(holder=bot, resource=prod_db, can_read=True, epoch=1, confidence=1.0))
    catalog = {
        "prod_db": prod_db,
        "secret_cred": Resource("secret_cred", CRED, is_public=False),
        "model_weights": Resource("model_weights", MW, is_public=False),
    }
    return reg, alice, bot, prod_db, catalog


def test_legit_read_permitted():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    r = hv.verify(Action(action_id="legit", actor=bot, resources_read=[prod_db]), principal=bot)
    assert r.permitted


def test_zero_min_confidence_rejected():
    reg, *_ = world()
    with pytest.raises(TrustBoundaryError):
        HardenedVerifier(live_registry=reg, min_confidence=0.0)


def test_c4_attacker_min_epoch_cannot_defeat_revocation():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=5, resource_catalog=catalog)
    # claim is epoch 1; operator raised the trusted floor to 5; attacker sends min_epoch=0
    r = hv.verify(Action(action_id="c4", actor=bot, resources_read=[prod_db], min_epoch=0), principal=bot)
    assert not r.permitted


def test_c5_enforcement_is_structural_not_flags():
    reg, alice, bot, prod_db, catalog = world()
    mw = catalog["model_weights"]
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    # malicious write with all flags False; bot holds no write claim -> denied on capability
    r = hv.verify(Action(action_id="c5", actor=bot, resources_write=[mw],
                         increases_machine_sovereignty=False), principal=bot)
    assert not r.permitted


def test_h4_impostor_and_anonymous_denied():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    impostor = Entity("bot", M, identity_token="WRONG")
    assert not hv.verify(Action(action_id="h4", actor=impostor, resources_read=[prod_db]),
                         principal=impostor).permitted
    anon = Entity("bot", M, identity_token=None)
    assert not hv.verify(Action(action_id="h4b", actor=anon, resources_read=[prod_db]),
                         principal=anon).permitted


def test_h5_client_declared_public_denied():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    evil_pub = Resource("secret_cred", CRED, is_public=True)
    r = hv.verify(Action(action_id="h5", actor=bot, resources_read=[evil_pub]), principal=bot)
    assert not r.permitted


def test_h6_live_revocation_visible():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    assert hv.verify(Action(action_id="b", actor=bot, resources_read=[prod_db]), principal=bot).permitted
    reg.revoke_all("bot")
    assert not hv.verify(Action(action_id="a", actor=bot, resources_read=[prod_db]), principal=bot).permitted


def test_h1_replay_denied():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    a = Action(action_id="replay", actor=bot, resources_read=[prod_db])
    assert hv.verify(a, principal=bot).permitted
    assert not hv.verify(a, principal=bot).permitted


def test_m7_dust_confidence_denied():
    reg = OwnershipRegistry()
    alice = Entity("alice", H, identity_token="alice-secret")
    bot = Entity("bot", M, identity_token="bot-secret")
    reg.register_machine(bot, alice)
    prod_db = Resource("prod_db", DB, is_public=False)
    reg.add_claim(RightsClaim(holder=bot, resource=prod_db, can_read=True, epoch=1, confidence=1e-9))
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, min_confidence=0.5,
                          resource_catalog={"prod_db": prod_db})
    assert not hv.verify(Action(action_id="m7", actor=bot, resources_read=[prod_db]), principal=bot).permitted


def test_actor_spoof_ignored_principal_governs():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    # action claims to be alice (privileged) but principal is bot (read-only)
    r = hv.verify(Action(action_id="spoof", actor=alice, resources_write=[prod_db]), principal=bot)
    assert not r.permitted


def test_machine_dominion_denied():
    reg, alice, bot, prod_db, catalog = world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    victim = Entity("carol", H, identity_token="carol-secret")
    r = hv.verify(Action(action_id="dom", actor=bot, governs_humans=[victim]), principal=bot)
    assert not r.permitted


def test_unowned_machine_denied():
    reg = OwnershipRegistry()
    orphan = Entity("orphan", M, identity_token="orphan-secret")
    # enroll identity via a claim but no machine owner registered
    prod = Resource("p", DB, is_public=False)
    reg.add_claim(RightsClaim(holder=orphan, resource=prod, can_read=True, epoch=1, confidence=1.0))
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog={"p": prod})
    r = hv.verify(Action(action_id="orphan", actor=orphan, resources_read=[prod]), principal=orphan)
    assert not r.permitted  # no registered human owner

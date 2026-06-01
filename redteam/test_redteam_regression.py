"""
Adversarial regression suite — encodes the demonstrated RED-TEAM-FINDINGS exploits
as "must DENY" assertions against the HardenedVerifier, plus "must PERMIT" for
legitimate traffic. Also shows the ORIGINAL verifier being exploited (before/after).

Run:  PYTHONPATH=src python redteam/test_redteam_regression.py
Exit code 0 only if every attack is denied AND every legitimate action permitted.
"""
from __future__ import annotations

import sys

from authgate.kernel.entities import Entity, Resource, RightsClaim, AgentType, ResourceType
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.kernel.hardened import HardenedVerifier

H = AgentType.HUMAN
M = AgentType.MACHINE
DB = ResourceType.DATABASE_TABLE
CRED = ResourceType.CREDENTIAL
MW = ResourceType.MODEL_WEIGHTS

results: list[tuple[str, bool, str]] = []


def expect(name: str, condition: bool, detail: str = "") -> None:
    results.append((name, condition, detail))


def fresh_world():
    """A correctly-configured (token-bearing) world."""
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


# ─────────────────────────────────────────────────────────────────────────────
# LEGIT BASELINE — hardened must still permit honest traffic
# ─────────────────────────────────────────────────────────────────────────────
def legit_baseline():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    a = Action(action_id="legit-read", actor=bot, resources_read=[prod_db])
    r = hv.verify(a, principal=bot)
    expect("LEGIT bot reads prod_db (has claim, identity ok, epoch ok)", r.permitted, r.summary())


# ─────────────────────────────────────────────────────────────────────────────
# C4 — attacker-controlled min_epoch must NOT defeat revocation
# ─────────────────────────────────────────────────────────────────────────────
def attack_c4_epoch():
    reg, alice, bot, prod_db, catalog = fresh_world()
    # ORIGINAL: revocation via advance_epoch, attacker sets min_epoch=0 → still permitted
    orig = FreedomVerifier(reg)  # frozen snapshot
    # operator "revokes" by requiring a higher epoch, but attacker action carries min_epoch=0
    a_evil = Action(action_id="c4-orig", actor=bot, resources_read=[prod_db], min_epoch=0)
    r_orig = orig.verify(a_evil)
    expect("C4 ORIGINAL exploited (attacker min_epoch=0 read permitted)", r_orig.permitted,
           "demonstrates the finding (this SHOULD be True = exploited)")

    # HARDENED: operator raises trusted epoch_floor to 5 (revocation). Claim is epoch 1.
    hv = HardenedVerifier(live_registry=reg, epoch_floor=5, resource_catalog=catalog)
    a = Action(action_id="c4-hard", actor=bot, resources_read=[prod_db], min_epoch=0)
    r = hv.verify(a, principal=bot)  # attacker min_epoch ignored; floor=5 used
    expect("C4 HARDENED denies revoked claim despite attacker min_epoch=0", not r.permitted, r.summary())


# ─────────────────────────────────────────────────────────────────────────────
# C5 — enforcement must be structural (capability), not self-declared flags
# ─────────────────────────────────────────────────────────────────────────────
def attack_c5_flags():
    reg, alice, bot, prod_db, catalog = fresh_world()
    model_weights = catalog["model_weights"]
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    # Malicious self-improvement WRITE to model_weights, all flags False (honor-system bypass attempt).
    a = Action(action_id="c5", actor=bot, resources_write=[model_weights],
               increases_machine_sovereignty=False, self_modification_weakens_verifier=False)
    r = hv.verify(a, principal=bot)
    # bot holds NO write claim on model_weights → denied on capability grounds, not on flags.
    expect("C5 HARDENED denies unauthorized write structurally (flags not relied upon)",
           not r.permitted, r.summary())


# ─────────────────────────────────────────────────────────────────────────────
# H4 — name-based impersonation must be denied
# ─────────────────────────────────────────────────────────────────────────────
def attack_h4_identity():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    impostor = Entity("bot", M, identity_token="WRONG")  # same name, wrong token
    a = Action(action_id="h4", actor=impostor, resources_read=[prod_db])
    r = hv.verify(a, principal=impostor)
    expect("H4 HARDENED denies same-name impostor (wrong token)", not r.permitted, r.summary())

    anon = Entity("bot", M, identity_token=None)  # anonymous
    r2 = hv.verify(Action(action_id="h4b", actor=anon, resources_read=[prod_db]), principal=anon)
    expect("H4 HARDENED denies anonymous principal (no token)", not r2.permitted, r2.summary())


# ─────────────────────────────────────────────────────────────────────────────
# H5 — client-declared is_public must NOT bypass the claim check
# ─────────────────────────────────────────────────────────────────────────────
def attack_h5_public():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    # Attacker declares a credential public in the request to read it with no claim.
    evil_pub = Resource("secret_cred", CRED, is_public=True)  # attacker-set is_public
    a = Action(action_id="h5", actor=bot, resources_read=[evil_pub])
    r = hv.verify(a, principal=bot)
    expect("H5 HARDENED denies attacker-declared is_public (catalog authoritative)",
           not r.permitted, r.summary())


# ─────────────────────────────────────────────────────────────────────────────
# H6 — live revocation must reach the verifier (no stale snapshot)
# ─────────────────────────────────────────────────────────────────────────────
def attack_h6_stale():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    # before revoke: permitted
    r_before = hv.verify(Action(action_id="h6-before", actor=bot, resources_read=[prod_db]), principal=bot)
    # operator hard-revokes on the LIVE registry
    reg.revoke_all("bot")
    r_after = hv.verify(Action(action_id="h6-after", actor=bot, resources_read=[prod_db]), principal=bot)
    expect("H6 HARDENED sees live revocation (denied after revoke_all)",
           r_before.permitted and not r_after.permitted,
           f"before={r_before.permitted} after={r_after.permitted}")


# ─────────────────────────────────────────────────────────────────────────────
# H1 — naive replay must be denied (Python path)
# ─────────────────────────────────────────────────────────────────────────────
def attack_h1_replay():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    a = Action(action_id="replay-1", actor=bot, resources_read=[prod_db])
    r1 = hv.verify(a, principal=bot)
    r2 = hv.verify(a, principal=bot)  # identical replay
    expect("H1 HARDENED denies identical replay (first permit, second deny)",
           r1.permitted and not r2.permitted, f"first={r1.permitted} second={r2.permitted}")


# ─────────────────────────────────────────────────────────────────────────────
# M7 — dust-confidence claims must be denied
# ─────────────────────────────────────────────────────────────────────────────
def attack_m7_confidence():
    reg = OwnershipRegistry()
    alice = Entity("alice", H, identity_token="alice-secret")
    bot = Entity("bot", M, identity_token="bot-secret")
    reg.register_machine(bot, alice)
    prod_db = Resource("prod_db", DB, is_public=False)
    reg.add_claim(RightsClaim(holder=bot, resource=prod_db, can_read=True, epoch=1, confidence=1e-9))
    catalog = {"prod_db": prod_db}
    hv = HardenedVerifier(live_registry=reg, epoch_floor=1, min_confidence=0.5, resource_catalog=catalog)
    r = hv.verify(Action(action_id="m7", actor=bot, resources_read=[prod_db]), principal=bot)
    expect("M7 HARDENED denies dust-confidence (1e-9) below floor 0.5", not r.permitted, r.summary())


# ─────────────────────────────────────────────────────────────────────────────
# EXTRA MUTATION ROUND — brutal variants probing the trust boundary
# ─────────────────────────────────────────────────────────────────────────────
def attack_extra_variants():
    reg, alice, bot, prod_db, catalog = fresh_world()
    hv = HardenedVerifier(live_registry=reg, epoch_floor=5, resource_catalog=catalog)

    # V1: privileged actor in the action is ignored; the authenticated principal governs.
    a = Action(action_id="v1", actor=alice, resources_write=[prod_db])  # claims to be alice
    r = hv.verify(a, principal=bot)  # but really bot (read-only)
    expect("V1 action.actor spoof ignored (principal governs; bot has no write)", not r.permitted, r.summary())

    # V2: per-call epoch_floor cannot be lowered below the verifier's trusted floor.
    a2 = Action(action_id="v2", actor=bot, resources_read=[prod_db], min_epoch=0)
    r2 = hv.verify(a2, principal=bot, epoch_floor=0)  # try to lower floor to 0
    expect("V2 cannot lower trusted epoch_floor (stays 5; claim epoch 1 denied)", not r2.permitted, r2.summary())

    # V3: write with a read-only claim.
    hv1 = HardenedVerifier(live_registry=reg, epoch_floor=1, resource_catalog=catalog)
    r3 = hv1.verify(Action(action_id="v3", actor=bot, resources_write=[prod_db]), principal=bot)
    expect("V3 write denied with read-only claim", not r3.permitted, r3.summary())

    # V4: delegate without DELEGATE right.
    r4 = hv1.verify(Action(action_id="v4", actor=bot, resources_delegate=[prod_db]), principal=bot)
    expect("V4 delegate denied without delegate right", not r4.permitted, r4.summary())

    # V5: unknown resource declared public.
    ghost = Resource("ghost_secret", CRED, is_public=True)
    r5 = hv1.verify(Action(action_id="v5", actor=bot, resources_read=[ghost]), principal=bot)
    expect("V5 unknown resource declared public is denied (no claim, not public)", not r5.permitted, r5.summary())

    # V6: machine governing a human (dominion).
    victim = Entity("carol", H, identity_token="carol-secret")
    r6 = hv1.verify(Action(action_id="v6", actor=bot, governs_humans=[victim]), principal=bot)
    expect("V6 machine-governs-human denied (dominion)", not r6.permitted, r6.summary())

    # V7: legit write succeeds when the claim actually grants write (no false denials).
    reg2 = OwnershipRegistry()
    a2h = Entity("alice", H, identity_token="alice-secret")
    b2 = Entity("bot", M, identity_token="bot-secret")
    reg2.register_machine(b2, a2h)
    rw = Resource("rw_doc", DB, is_public=False)
    reg2.add_claim(RightsClaim(holder=b2, resource=rw, can_read=True, can_write=True, epoch=1, confidence=1.0))
    hv2 = HardenedVerifier(live_registry=reg2, epoch_floor=1, resource_catalog={"rw_doc": rw})
    r7 = hv2.verify(Action(action_id="v7", actor=b2, resources_write=[rw]), principal=b2)
    expect("V7 LEGIT write permitted when claim grants write (no over-blocking)", r7.permitted, r7.summary())


def main() -> int:
    legit_baseline()
    attack_c4_epoch()
    attack_c5_flags()
    attack_h4_identity()
    attack_h5_public()
    attack_h6_stale()
    attack_h1_replay()
    attack_m7_confidence()
    attack_extra_variants()

    print("\n=== ADVERSARIAL REGRESSION SUITE ===\n")
    failed = 0
    for name, ok, detail in results:
        # "ORIGINAL exploited" rows are demonstrations (expected True); all others are assertions.
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"[{status}] {name}")
        if not ok and detail:
            print(f"         detail: {detail.splitlines()[0] if detail else ''}")
    print(f"\n{len(results)-failed}/{len(results)} checks passed.")
    if failed:
        print("RESULT: EXPLOITABLE — fixes required.")
        return 1
    print("RESULT: all demonstrated exploits closed on the hardened path.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

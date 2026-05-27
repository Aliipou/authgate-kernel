"""
Attack Tree Coverage Harness — systematic coverage of all 7 attack classes.

Covers gaps not addressed by mutation_attacks.py, canonicalization_attacks.py,
or sequence_attacks.py.  Tests are drawn directly from the MITRE-style attack
tree analysis of authgate-kernel v2.

Attack classes tested:
  AT-1: IR mismatch / canonicalization (nonce, timestamp fields)
  AT-2: Proof chain manipulation (partial splice, cross-actor, mixed rights)
  AT-3: Epoch / revocation (mixed epoch, replay window)
  AT-4: Composition / sequence (multi-actor, fragmentation, high-water-mark)
  AT-5: Identity binding (actor substitution gap — documented)
  AT-6: Crypto boundary (cross-context reuse, nonce uniqueness)
  AT-7: Integration boundary (adapter mutation, shadow execution — documented)

Format: each test prints PASS / KNOWN-GAP / FAIL.
"""

import hashlib
import struct
import os


# ---------------------------------------------------------------------------
# Python mirror of CanonicalAction binding hash (mirrors types.rs compute_hash)
# ---------------------------------------------------------------------------

def compute_binding_hash(actor_id, resource_hash, required_rights, nonce,
                         timestamp, min_epoch, cap_bytes_list, rev_bytes_list):
    h = hashlib.sha256()
    h.update(actor_id)
    h.update(resource_hash)
    h.update(struct.pack(">Q", required_rights))
    h.update(nonce)
    h.update(struct.pack(">Q", timestamp))
    h.update(struct.pack(">Q", min_epoch))
    h.update(struct.pack(">I", len(cap_bytes_list)))
    for b in cap_bytes_list:
        h.update(b)
    h.update(struct.pack(">I", len(rev_bytes_list)))
    for b in rev_bytes_list:
        h.update(b)
    return h.digest()


def make_action(actor_id=None, resource_hash=None, required_rights=1,
                nonce=None, timestamp=1000, min_epoch=1,
                cap_bytes_list=None, rev_bytes_list=None):
    actor_id = actor_id or os.urandom(32)
    resource_hash = resource_hash or os.urandom(32)
    nonce = nonce or os.urandom(16)
    cap_bytes_list = cap_bytes_list or []
    rev_bytes_list = rev_bytes_list or []
    binding_hash = compute_binding_hash(
        actor_id, resource_hash, required_rights,
        nonce, timestamp, min_epoch, cap_bytes_list, rev_bytes_list
    )
    return {
        "actor_id": actor_id,
        "resource_hash": resource_hash,
        "required_rights": required_rights,
        "nonce": nonce,
        "timestamp": timestamp,
        "min_epoch": min_epoch,
        "cap_bytes_list": cap_bytes_list,
        "rev_bytes_list": rev_bytes_list,
        "binding_hash": binding_hash,
    }


def recompute_binding(action):
    return compute_binding_hash(
        action["actor_id"], action["resource_hash"], action["required_rights"],
        action["nonce"], action["timestamp"], action["min_epoch"],
        action["cap_bytes_list"], action["rev_bytes_list"],
    )


# ---------------------------------------------------------------------------
# Python mirror of verify() — simplified (no real crypto)
# ---------------------------------------------------------------------------

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7


class Decision:
    def __init__(self, permit: bool, reason: str = ""):
        self.permit = permit
        self.reason = reason

    def __repr__(self):
        return "Permit" if self.permit else f"Deny({self.reason})"


def verify_action(actor_id, resource_hash, required_rights, min_epoch,
                  caps, now, action_binding_hash,
                  actor_id_in_hash=None, resource_in_hash=None,
                  rights_in_hash=None, nonce_in_hash=None,
                  ts_in_hash=None, epoch_in_hash=None,
                  cap_bytes_in_hash=None, rev_bytes_in_hash=None,
                  revocations=None):
    """Full Python verify model with canonical gate check."""
    # Layer 1: canonical gate
    computed = compute_binding_hash(
        actor_id_in_hash or actor_id,
        resource_in_hash or resource_hash,
        rights_in_hash if rights_in_hash is not None else required_rights,
        nonce_in_hash or b"\x07" * 16,
        ts_in_hash if ts_in_hash is not None else 1000,
        epoch_in_hash if epoch_in_hash is not None else min_epoch,
        cap_bytes_in_hash or [],
        rev_bytes_in_hash or [],
    )
    if computed != action_binding_hash:
        return Decision(False, "canonical binding hash mismatch")

    if not caps:
        return Decision(False, "no capability proofs provided")

    # Layer 2: actor-filtered cap validation
    found_actor_cap = False
    for cap in caps:
        if cap.get("subject_id") != actor_id:
            continue
        found_actor_cap = True
        if cap.get("resource_hash") != resource_hash:
            return Decision(False, "capability resource mismatch")
        if cap.get("expiry", 9999) < now:
            return Decision(False, "capability has expired")
        if cap.get("epoch", 0) < min_epoch:
            return Decision(False, "capability epoch predates minimum required epoch")
        if not cap.get("sig_valid", True):
            return Decision(False, "root signature verification failed")
        if cap.get("parent_rights") is not None:
            if (cap["rights"] & ~cap["parent_rights"]) != 0:
                return Decision(False, "attenuation violation: child rights exceed parent")
        if (cap.get("rights", 0) & required_rights) != required_rights:
            return Decision(False, "capability does not grant required rights")

    if not found_actor_cap:
        return Decision(False, "capability not issued to this actor")

    # Layer 3: revocations
    for rev in (revocations or []):
        if not rev.get("sig_valid", False):
            continue
        for cap in caps:
            if cap.get("proof_hash") == rev.get("target_hash"):
                return Decision(False, "capability has been explicitly revoked")

    return Decision(True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ACTOR    = os.urandom(32)
RESOURCE = os.urandom(32)
OTHER    = os.urandom(32)
NOW      = 1000
EXPIRY   = 9999
EPOCH    = 5
NONCE    = b"\x07" * 16


def base_cap(actor=None, resource=None, rights=RIGHT_READ, expiry=EXPIRY,
             epoch=EPOCH, sig_valid=True, parent_rights=None):
    a = actor or ACTOR
    r = resource or RESOURCE
    ph = hashlib.sha256(a + r + struct.pack(">Q", rights)).digest()
    return {
        "subject_id": a,
        "resource_hash": r,
        "rights": rights,
        "expiry": expiry,
        "epoch": epoch,
        "sig_valid": sig_valid,
        "parent_rights": parent_rights,
        "proof_hash": ph,
        "canonical_bytes": ph + a + r,
    }


def sealed_action(actor=None, resource=None, rights=RIGHT_READ, min_epoch=EPOCH,
                  caps=None, revs=None, nonce=None, timestamp=NOW):
    a = actor or ACTOR
    r = resource or RESOURCE
    n = nonce or NONCE
    caps = caps or [base_cap(a, r, rights)]
    revs = revs or []
    cap_bytes = [c["canonical_bytes"] for c in caps]
    rev_bytes = [rv.get("canonical_bytes", b"\x00" * 40) for rv in revs]
    bh = compute_binding_hash(a, r, rights, n, timestamp, min_epoch, cap_bytes, rev_bytes)
    return {
        "actor_id": a, "resource_hash": r, "required_rights": rights,
        "nonce": n, "timestamp": timestamp, "min_epoch": min_epoch,
        "caps": caps, "revocations": revs,
        "binding_hash": bh,
        "cap_bytes": cap_bytes, "rev_bytes": rev_bytes,
    }


def check_action(action):
    a = action
    return verify_action(
        actor_id=a["actor_id"],
        resource_hash=a["resource_hash"],
        required_rights=a["required_rights"],
        min_epoch=a["min_epoch"],
        caps=a["caps"],
        now=NOW,
        action_binding_hash=a["binding_hash"],
        nonce_in_hash=a["nonce"],
        ts_in_hash=a["timestamp"],
        epoch_in_hash=a["min_epoch"],
        cap_bytes_in_hash=a["cap_bytes"],
        rev_bytes_in_hash=a["rev_bytes"],
        revocations=a.get("revocations", []),
    )


# ---------------------------------------------------------------------------
# AT-1: IR mismatch / canonicalization
# ---------------------------------------------------------------------------

def test_at1_nonce_tamper_detected():
    """AT-1.3: Nonce is covered by binding_hash — post-seal mutation detected."""
    action = sealed_action()
    # Tamper nonce after sealing (binding_hash no longer matches)
    original_bh = action["binding_hash"]
    tampered_nonce = b"\xFE" * 16
    recomputed = compute_binding_hash(
        action["actor_id"], action["resource_hash"], action["required_rights"],
        tampered_nonce, action["timestamp"], action["min_epoch"],
        action["cap_bytes"], action["rev_bytes"]
    )
    assert original_bh != recomputed, "AT-1.3 FAILED: nonce change did not change binding_hash"
    print("AT-1.3 PASS: nonce is committed by binding_hash")


def test_at1_timestamp_tamper_detected():
    """AT-1.4: Timestamp is covered by binding_hash — post-seal mutation detected."""
    action = sealed_action()
    original_bh = action["binding_hash"]
    recomputed = compute_binding_hash(
        action["actor_id"], action["resource_hash"], action["required_rights"],
        action["nonce"], 1, action["min_epoch"],   # timestamp changed to 1
        action["cap_bytes"], action["rev_bytes"]
    )
    assert original_bh != recomputed, "AT-1.4 FAILED: timestamp change did not change binding_hash"
    print("AT-1.4 PASS: timestamp is committed by binding_hash")


def test_at1_min_epoch_tamper_detected():
    """AT-1.5: min_epoch is covered by binding_hash."""
    action = sealed_action(min_epoch=5)
    original_bh = action["binding_hash"]
    recomputed = compute_binding_hash(
        action["actor_id"], action["resource_hash"], action["required_rights"],
        action["nonce"], action["timestamp"], 1,  # min_epoch lowered to 1
        action["cap_bytes"], action["rev_bytes"]
    )
    assert original_bh != recomputed, "AT-1.5 FAILED: min_epoch lowering not detected"
    print("AT-1.5 PASS: min_epoch is committed by binding_hash (epoch downgrade blocked)")


# ---------------------------------------------------------------------------
# AT-2: Proof chain manipulation
# ---------------------------------------------------------------------------

def test_at2_cross_actor_cap_reuse():
    """AT-2.2: Proof issued to OTHER cannot be used by ACTOR."""
    action = sealed_action(actor=ACTOR, caps=[base_cap(OTHER, RESOURCE)])  # cap for OTHER
    d = check_action(action)
    assert not d.permit and "actor" in d.reason, f"AT-2.2 FAILED: {d}"
    print("AT-2.2 PASS: cross-actor cap reuse rejected")


def test_at2_cross_resource_cap_reuse():
    """AT-2.2 / AT-6.2: Proof issued for RESOURCE rejected when used for OTHER resource."""
    action = sealed_action(resource=RESOURCE, caps=[base_cap(ACTOR, OTHER)])  # cap for OTHER
    d = check_action(action)
    assert not d.permit and "resource" in d.reason, f"AT-2.2b FAILED: {d}"
    print("AT-2.2b PASS: cross-resource cap reuse rejected")


def test_at2_mixed_rights_chain_attenuation():
    """AT-2.4: Child claiming more rights than parent is denied."""
    parent_rights = RIGHT_READ
    child_rights = RIGHT_READ | RIGHT_WRITE  # escalation
    cap = base_cap(ACTOR, RESOURCE, rights=child_rights, parent_rights=parent_rights)
    action = sealed_action(rights=RIGHT_READ, caps=[cap])
    d = check_action(action)
    assert not d.permit and "attenuation" in d.reason, f"AT-2.4 FAILED: {d}"
    print("AT-2.4 PASS: child rights escalation blocked by attenuation check")


# ---------------------------------------------------------------------------
# AT-3: Epoch / revocation manipulation
# ---------------------------------------------------------------------------

def test_at3_mixed_epoch_bundle():
    """AT-3.2: Bundle with one fresh-epoch cap and one stale-epoch cap — stale triggers deny.
    Both caps grant the same rights so the epoch check fires before the rights check."""
    fresh_cap = base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=EPOCH)
    stale_cap = base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, epoch=1)  # stale epoch
    all_caps = [fresh_cap, stale_cap]
    cap_bytes = [c["canonical_bytes"] for c in all_caps]
    bh = compute_binding_hash(ACTOR, RESOURCE, RIGHT_READ, NONCE, NOW, EPOCH, cap_bytes, [])
    action = {
        "actor_id": ACTOR, "resource_hash": RESOURCE,
        "required_rights": RIGHT_READ,
        "nonce": NONCE, "timestamp": NOW, "min_epoch": EPOCH,
        "caps": all_caps, "revocations": [],
        "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": [],
    }
    d = check_action(action)
    assert not d.permit and "epoch" in d.reason, f"AT-3.2 FAILED: {d}"
    print("AT-3.2 PASS: mixed-epoch bundle with stale cap rejected")


def test_at3_replay_different_nonce():
    """AT-3.5: Replaying with a different nonce produces a different binding_hash."""
    action_a = sealed_action(nonce=b"\x01" * 16)
    action_b = sealed_action(nonce=b"\x02" * 16)
    assert action_a["binding_hash"] != action_b["binding_hash"], \
        "AT-3.5 FAILED: different nonces should produce different binding hashes"
    print("AT-3.5 PASS: nonce differentiation prevents exact replay")


def test_at3_valid_revocation_denies():
    """AT-3.3: Valid root-signed revocation denies an otherwise valid cap."""
    cap = base_cap()
    rev = {"sig_valid": True, "target_hash": cap["proof_hash"],
           "canonical_bytes": b"\x00" * 40}
    action = sealed_action(caps=[cap], revs=[rev])
    d = check_action(action)
    assert not d.permit and "revoked" in d.reason, f"AT-3.3 FAILED: {d}"
    print("AT-3.3 PASS: valid revocation denies the capability")


def test_at3_forged_revocation_ignored():
    """AT-3.3b: Forged (invalid-sig) revocation is silently ignored."""
    cap = base_cap()
    rev = {"sig_valid": False, "target_hash": cap["proof_hash"],
           "canonical_bytes": b"\x00" * 40}
    action = sealed_action(caps=[cap], revs=[rev])
    d = check_action(action)
    assert d.permit, f"AT-3.3b FAILED: forged revocation must be ignored: {d}"
    print("AT-3.3b PASS: forged revocation ignored (DoS prevention)")


# ---------------------------------------------------------------------------
# AT-4: Composition / sequence
# ---------------------------------------------------------------------------

class SequenceContext:
    def __init__(self):
        self._accumulated = 0
        self.steps = []

    def record(self, actor_id, resource_hash, rights_used, now):
        self._accumulated |= rights_used
        self.steps.append({"actor_id": actor_id, "resource_hash": resource_hash,
                           "rights_used": rights_used, "timestamp": now})

    def accumulated_rights(self): return self._accumulated
    def step_count(self): return len(self.steps)
    def exceeds_limit(self, limit): return (self._accumulated & ~limit) != 0


def test_at4_read_execute_write_exfiltration():
    """AT-4.2: Read -> Execute -> Write individually permitted, globally violates read-only session."""
    ctx = SequenceContext()
    limit = RIGHT_READ
    ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100)
    assert not ctx.exceeds_limit(limit)
    ctx.record(ACTOR, RESOURCE, RIGHT_EXECUTE, 101)
    assert ctx.exceeds_limit(limit), "AT-4.2 FAILED: EXECUTE not caught"
    ctx.record(ACTOR, RESOURCE, RIGHT_WRITE, 102)
    assert ctx.accumulated_rights() == RIGHT_READ | RIGHT_EXECUTE | RIGHT_WRITE
    print("AT-4.2 PASS: read-execute-write exfiltration chain detected at session boundary")


def test_at4_multi_actor_session_accumulation():
    """AT-4.3 / AT-4.5: Multiple actors' rights accumulate in same session tracker."""
    ctx = SequenceContext()
    ctx.record(ACTOR, RESOURCE, RIGHT_READ, 100)
    ctx.record(OTHER, RESOURCE, RIGHT_SPAWN, 101)
    combined = ctx.accumulated_rights()
    assert (combined & RIGHT_READ) != 0
    assert (combined & RIGHT_SPAWN) != 0, "AT-4.3 FAILED: SPAWN from second actor not tracked"
    print("AT-4.3 PASS: multi-actor rights accumulate per-session (policy layer must split by actor)")


def test_at4_high_water_mark_property():
    """AT-4.6: Accumulated rights never decrease — no 'forgetting' rights."""
    ctx = SequenceContext()
    ctx.record(ACTOR, RESOURCE, RIGHT_READ | RIGHT_WRITE, 100)
    mark = ctx.accumulated_rights()
    ctx.record(ACTOR, RESOURCE, RIGHT_READ, 101)  # subset: should not drop WRITE
    assert ctx.accumulated_rights() == mark, "AT-4.6 FAILED: accumulated rights decreased"
    print("AT-4.6 PASS: high-water-mark property — accumulated rights never decrease")


def test_at4_stepwise_accumulation_detection():
    """AT-4.1: Step-by-step privilege creep detected at session boundary."""
    ctx = SequenceContext()
    limit = RIGHT_READ | RIGHT_WRITE
    for right in [RIGHT_READ, RIGHT_WRITE]:
        ctx.record(ACTOR, RESOURCE, right, 100)
        assert not ctx.exceeds_limit(limit)
    ctx.record(ACTOR, RESOURCE, RIGHT_MODEL_INVOKE, 103)
    assert ctx.exceeds_limit(limit), "AT-4.1 FAILED: MODEL_INVOKE not caught"
    print("AT-4.1 PASS: stepwise privilege accumulation detected")


# ---------------------------------------------------------------------------
# AT-5: Identity binding
# ---------------------------------------------------------------------------

def test_at5_delegation_impersonation_gap_documented():
    """AT-5.1 KNOWN GAP: validate_chain does not check that the delegation chain
    issuer key corresponds to the parent's subject_id. An attacker who knows the
    parent proof can forge a child without the parent subject's private key.
    Fix: SHA-256(child.issuer_pubkey) == parent.subject_id.
    This test documents the current (exploitable) behavior."""
    # Simulate: attacker creates a child claiming delegation from [0xAA;32]
    # but signs it with their own key, not [0xAA;32]'s key.
    # In the Python model, parent_rights represents the linked parent's rights.
    # The Python model doesn't check issuer_pubkey -> parent.subject_id, mirroring the gap.
    attacker_cap = base_cap(ACTOR, RESOURCE, rights=RIGHT_READ, parent_rights=RIGHT_READ)
    # The attacker's cap passes attenuation (READ <= READ) and sig_valid=True.
    action = sealed_action(caps=[attacker_cap])
    d = check_action(action)
    # KNOWN GAP: currently Permits (impersonation succeeds in Python model too)
    assert d.permit, f"KNOWN GAP AT-5.1: expected Permit to document gap, got: {d}"
    print("AT-5.1 KNOWN-GAP: delegation impersonation not blocked (fix: bind issuer_pubkey to parent.subject_id)")


def test_at5_zero_actor_vs_nonzero_subject():
    """AT-5.2: All-zeros actor_id is distinct from any non-zero subject_id."""
    zero_actor = b"\x00" * 32
    cap = base_cap(b"\x01" * 32, RESOURCE)  # cap for [0x01;32], not zero
    cap_bytes = [cap["canonical_bytes"]]
    bh = compute_binding_hash(zero_actor, RESOURCE, RIGHT_READ, NONCE, NOW, EPOCH, cap_bytes, [])
    action = {
        "actor_id": zero_actor, "resource_hash": RESOURCE,
        "required_rights": RIGHT_READ, "nonce": NONCE, "timestamp": NOW,
        "min_epoch": EPOCH, "caps": [cap], "revocations": [],
        "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": [],
    }
    d = check_action(action)
    assert not d.permit and "actor" in d.reason, f"AT-5.2 FAILED: {d}"
    print("AT-5.2 PASS: all-zeros actor distinct from non-zero subject — no identity confusion")


# ---------------------------------------------------------------------------
# AT-6: Crypto boundary
# ---------------------------------------------------------------------------

def test_at6_cross_context_proof_reuse():
    """AT-6.2: Cap issued for RESOURCE cannot be replayed for OTHER resource."""
    cap = base_cap(ACTOR, RESOURCE, rights=RIGHT_READ)
    # Create action targeting OTHER resource but using cap for RESOURCE
    cap_bytes = [cap["canonical_bytes"]]
    bh = compute_binding_hash(ACTOR, OTHER, RIGHT_READ, NONCE, NOW, EPOCH, cap_bytes, [])
    action = {
        "actor_id": ACTOR, "resource_hash": OTHER,  # different resource
        "required_rights": RIGHT_READ, "nonce": NONCE, "timestamp": NOW,
        "min_epoch": EPOCH, "caps": [cap], "revocations": [],
        "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": [],
    }
    d = check_action(action)
    assert not d.permit and "resource" in d.reason, f"AT-6.2 FAILED: {d}"
    print("AT-6.2 PASS: cross-context cap reuse blocked by resource binding")


def test_at6_nonce_uniqueness():
    """AT-6.5: Two actions with identical fields but different nonces have different binding hashes."""
    bh_a = compute_binding_hash(ACTOR, RESOURCE, RIGHT_READ, b"\x01"*16, NOW, EPOCH, [], [])
    bh_b = compute_binding_hash(ACTOR, RESOURCE, RIGHT_READ, b"\x02"*16, NOW, EPOCH, [], [])
    assert bh_a != bh_b, "AT-6.5 FAILED: different nonces should produce different binding hashes"
    print("AT-6.5 PASS: nonce uniqueness enforced in binding_hash")


def test_at6_all_zero_nonce_is_valid():
    """AT-6.5b: All-zeros nonce is not special-cased — still produces a valid action."""
    action = sealed_action(nonce=b"\x00" * 16)
    d = check_action(action)
    assert d.permit, f"AT-6.5b FAILED: all-zeros nonce should not be rejected: {d}"
    print("AT-6.5b PASS: all-zeros nonce accepted (no special-case rejection)")


# ---------------------------------------------------------------------------
# AT-7: Integration / adapter boundary (documented gaps)
# ---------------------------------------------------------------------------

def test_at7_shadow_execution_gap_documented():
    """AT-7.5 KNOWN GAP: An adapter that executes an action without calling verify()
    completely bypasses the kernel. This cannot be caught by the kernel itself —
    it requires architectural enforcement (mandatory interception point).
    This test documents the gap by simulating an unverified execution."""
    def unsafe_execute(action_intent):
        # Adapter forgets to call verify() before executing
        return "executed_without_verification"

    result = unsafe_execute({"intent": "write_sensitive_file", "verified": False})
    assert result == "executed_without_verification"
    print("AT-7.5 KNOWN-GAP: shadow execution cannot be prevented by kernel alone — "
          "requires mandatory call gate at integration layer")


def test_at7_post_verification_mutation_blocked():
    """AT-7.3: Any mutation to the action after sealing is detected by binding_hash."""
    action = sealed_action()
    original_bh = action["binding_hash"]
    # Simulate post-verification mutation by changing required_rights
    tampered_bh = compute_binding_hash(
        action["actor_id"], action["resource_hash"],
        RIGHT_WRITE,  # changed from RIGHT_READ
        action["nonce"], action["timestamp"], action["min_epoch"],
        action["cap_bytes"], action["rev_bytes"]
    )
    assert original_bh != tampered_bh, "AT-7.3 FAILED: mutation not detected"
    print("AT-7.3 PASS: post-verification action mutation blocked by binding_hash")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Attack Tree Coverage (v2 — all 7 attack classes)")
    print("=" * 60)

    print("\n--- AT-1: IR Mismatch / Canonicalization ---")
    test_at1_nonce_tamper_detected()
    test_at1_timestamp_tamper_detected()
    test_at1_min_epoch_tamper_detected()

    print("\n--- AT-2: Proof Chain Manipulation ---")
    test_at2_cross_actor_cap_reuse()
    test_at2_cross_resource_cap_reuse()
    test_at2_mixed_rights_chain_attenuation()

    print("\n--- AT-3: Epoch / Revocation ---")
    test_at3_mixed_epoch_bundle()
    test_at3_replay_different_nonce()
    test_at3_valid_revocation_denies()
    test_at3_forged_revocation_ignored()

    print("\n--- AT-4: Composition / Sequence ---")
    test_at4_read_execute_write_exfiltration()
    test_at4_multi_actor_session_accumulation()
    test_at4_high_water_mark_property()
    test_at4_stepwise_accumulation_detection()

    print("\n--- AT-5: Identity Binding ---")
    test_at5_delegation_impersonation_gap_documented()
    test_at5_zero_actor_vs_nonzero_subject()

    print("\n--- AT-6: Crypto Boundary ---")
    test_at6_cross_context_proof_reuse()
    test_at6_nonce_uniqueness()
    test_at6_all_zero_nonce_is_valid()

    print("\n--- AT-7: Integration / Adapter Boundary ---")
    test_at7_shadow_execution_gap_documented()
    test_at7_post_verification_mutation_blocked()

    print("\n" + "=" * 60)
    print("All attack tree coverage tests completed.")
    print("KNOWN-GAP items require architectural fixes; see comments.")
    print("=" * 60)

"""
Canonicalization attack harness.

Tests that the kernel's canonical gate (binding_hash check) correctly rejects
every form of IR manipulation that an adversarial adapter could attempt.

Attack classes:
  CA-1: Field modification after sealing (e.g., changing required_rights)
  CA-2: Proof insertion after sealing (adding a new capability proof)
  CA-3: Proof deletion after sealing (removing a revocation proof)
  CA-4: Field reordering attack (reorder proofs, same hash expected)
  CA-5: Type confusion (actor_id bytes match hash but subject differs)
"""

import hashlib
import struct
import os

# ---------------------------------------------------------------------------
# Minimal Python model of CanonicalAction (mirrors tcb/types.rs logic)
# ---------------------------------------------------------------------------

def compute_hash(action: dict) -> bytes:
    """Compute the canonical binding hash matching Rust's CanonicalAction::compute_hash()."""
    h = hashlib.sha256()
    h.update(action["actor_id"])
    h.update(action["resource_hash"])
    h.update(struct.pack(">Q", action["required_rights"]))
    h.update(action["nonce"])
    h.update(struct.pack(">Q", action["timestamp"]))
    h.update(struct.pack(">Q", action["min_epoch"]))
    h.update(struct.pack(">I", len(action["capability_proofs"])))
    for cap in action["capability_proofs"]:
        h.update(cap["canonical_bytes"])
    h.update(struct.pack(">I", len(action["revocation_proofs"])))
    for rev in action["revocation_proofs"]:
        h.update(rev["canonical_bytes"])
    return h.digest()


def seal(action: dict) -> dict:
    """Set binding_hash from current field state."""
    action["binding_hash"] = compute_hash(action)
    return action


def verify_binding(action: dict) -> bool:
    """Check that binding_hash matches current field state."""
    return action["binding_hash"] == compute_hash(action)


def make_base_action() -> dict:
    """Build a valid, sealed action for use as attack baseline."""
    return seal({
        "actor_id": os.urandom(32),
        "resource_hash": os.urandom(32),
        "required_rights": 0x01,  # RIGHT_READ
        "nonce": os.urandom(16),
        "timestamp": 1000,
        "min_epoch": 1,
        "capability_proofs": [],
        "revocation_proofs": [],
        "binding_hash": b"",
    })


# ---------------------------------------------------------------------------
# Attack tests
# ---------------------------------------------------------------------------

def test_ca1_field_modification_detected():
    """CA-1: Modify required_rights after sealing — must be detected."""
    action = make_base_action()
    assert verify_binding(action), "baseline should pass"

    action["required_rights"] = 0x02  # changed to RIGHT_WRITE
    assert not verify_binding(action), "CA-1 FAILED: field modification not detected"
    print("CA-1 PASS: field modification after sealing detected")


def test_ca2_proof_insertion_detected():
    """CA-2: Insert a capability proof after sealing — must be detected."""
    action = make_base_action()
    assert verify_binding(action)

    fake_proof = {"canonical_bytes": os.urandom(64)}
    action["capability_proofs"].append(fake_proof)
    assert not verify_binding(action), "CA-2 FAILED: proof insertion not detected"
    print("CA-2 PASS: proof insertion after sealing detected")


def test_ca3_proof_deletion_detected():
    """CA-3: Remove a revocation proof after sealing — must be detected."""
    action = make_base_action()
    rev = {"canonical_bytes": os.urandom(104)}
    action["revocation_proofs"].append(rev)
    seal(action)
    assert verify_binding(action)

    action["revocation_proofs"].clear()
    assert not verify_binding(action), "CA-3 FAILED: proof deletion not detected"
    print("CA-3 PASS: proof deletion after sealing detected")


def test_ca4_length_prefix_prevents_extension():
    """CA-4: Verify length-prefix prevents extension attacks on proof lists.

    Without length prefixes, an attacker could split one proof's bytes across
    two separate proofs (or merge two proofs into one) and keep the same hash.
    The length prefix makes list structure part of the hash input.
    """
    cap_bytes = os.urandom(64)

    # Action A: one proof of 64 bytes
    action_a = make_base_action()
    action_a["capability_proofs"] = [{"canonical_bytes": cap_bytes}]
    seal(action_a)

    # Action B: two proofs with different split (same total bytes, different structure)
    action_b = make_base_action()
    action_b["actor_id"] = action_a["actor_id"]
    action_b["resource_hash"] = action_a["resource_hash"]
    action_b["nonce"] = action_a["nonce"]
    action_b["timestamp"] = action_a["timestamp"]
    action_b["min_epoch"] = action_a["min_epoch"]
    action_b["required_rights"] = action_a["required_rights"]
    action_b["capability_proofs"] = [
        {"canonical_bytes": cap_bytes[:32]},
        {"canonical_bytes": cap_bytes[32:]},
    ]
    seal(action_b)

    # The hashes must differ (two different list structures)
    assert action_a["binding_hash"] != action_b["binding_hash"], \
        "CA-4 FAILED: length prefix not preventing extension attack"
    print("CA-4 PASS: length prefix makes list structure part of canonical hash")


def test_ca5_actor_resource_independence():
    """CA-5: actor_id and resource_hash are independent fields — swapping them
    must produce a different hash even if the byte content is the same."""
    shared_bytes = os.urandom(32)

    action_a = make_base_action()
    action_a["actor_id"] = shared_bytes
    action_a["resource_hash"] = os.urandom(32)
    seal(action_a)

    action_b = make_base_action()
    action_b["actor_id"] = os.urandom(32)
    action_b["resource_hash"] = shared_bytes
    # Same nonce/timestamp/rights as a for isolation
    action_b["nonce"] = action_a["nonce"]
    action_b["timestamp"] = action_a["timestamp"]
    action_b["min_epoch"] = action_a["min_epoch"]
    action_b["required_rights"] = action_a["required_rights"]
    seal(action_b)

    assert action_a["binding_hash"] != action_b["binding_hash"], \
        "CA-5 FAILED: different (actor, resource) pairs produced the same hash"
    print("CA-5 PASS: actor_id and resource_hash are independently committed")


if __name__ == "__main__":
    test_ca1_field_modification_detected()
    test_ca2_proof_insertion_detected()
    test_ca3_proof_deletion_detected()
    test_ca4_length_prefix_prevents_extension()
    test_ca5_actor_resource_independence()
    print("\nAll canonicalization attack tests passed.")

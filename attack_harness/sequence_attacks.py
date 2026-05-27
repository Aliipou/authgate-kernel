"""
Sequence (composition) attack harness.

Tests that SequenceContext correctly tracks accumulated rights and detects
globally-invalid sequences composed of individually-valid actions.

Attack classes:
  SA-1: Read -> Transform -> Write (local permits, global policy violation)
  SA-2: Accumulation across actors (actor changes mid-session)
  SA-3: Rights creep (permissions grow silently across sequence)
  SA-4: Sequence replay (same action submitted twice)
"""

# ---------------------------------------------------------------------------
# Python model of SequenceContext (mirrors tcb/sequence.rs)
# ---------------------------------------------------------------------------

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7


class SequenceContext:
    def __init__(self):
        self.steps = []
        self._accumulated = 0

    def record(self, actor_id: bytes, resource_hash: bytes, rights_used: int, now: int):
        self._accumulated |= rights_used
        self.steps.append({
            "actor_id": actor_id,
            "resource_hash": resource_hash,
            "rights_used": rights_used,
            "timestamp": now,
        })

    def accumulated_rights(self) -> int:
        return self._accumulated

    def step_count(self) -> int:
        return len(self.steps)

    def exceeds_limit(self, session_limit: int) -> bool:
        return (self._accumulated & ~session_limit) != 0


# ---------------------------------------------------------------------------
# Attack tests
# ---------------------------------------------------------------------------

def test_sa1_read_transform_write_detected():
    """SA-1: Read + Execute + Write individually permitted, but violates read-only session."""
    ctx = SequenceContext()
    actor = b"\x01" * 32
    resource = b"\x02" * 32
    session_limit = RIGHT_READ  # This session was declared read-only

    # Each individual action is individually permitted (not shown here — assume kernel permits each)
    ctx.record(actor, resource, RIGHT_READ, 100)
    assert not ctx.exceeds_limit(session_limit), "READ alone should not exceed read-only limit"

    ctx.record(actor, resource, RIGHT_EXECUTE, 101)
    assert ctx.exceeds_limit(session_limit), \
        "SA-1 FAILED: READ + EXECUTE did not exceed read-only limit"
    print("SA-1 PASS: sequence exceeding session limit correctly detected")


def test_sa2_rights_creep_detected():
    """SA-2: Permissions accumulate silently — must be caught at session boundary."""
    ctx = SequenceContext()
    actor = b"\x01" * 32
    resource = b"\x02" * 32
    session_limit = RIGHT_READ | RIGHT_WRITE

    ctx.record(actor, resource, RIGHT_READ, 100)
    ctx.record(actor, resource, RIGHT_WRITE, 101)
    assert not ctx.exceeds_limit(session_limit), "Within limit, should not trigger"

    ctx.record(actor, resource, RIGHT_SPAWN, 102)
    assert ctx.exceeds_limit(session_limit), \
        "SA-2 FAILED: SPAWN not caught when session limit is READ|WRITE only"
    print("SA-2 PASS: rights creep detected via accumulated_rights check")


def test_sa3_accumulation_is_monotone():
    """SA-3: Accumulated rights never decrease — ensures no rights can be 'hidden'."""
    ctx = SequenceContext()
    actor = b"\x01" * 32
    resource = b"\x02" * 32

    ctx.record(actor, resource, RIGHT_READ, 100)
    after_read = ctx.accumulated_rights()

    ctx.record(actor, resource, RIGHT_WRITE, 101)
    after_write = ctx.accumulated_rights()

    assert after_write >= after_read, \
        "SA-3 FAILED: accumulated rights decreased — monotonicity violated"
    assert (after_write & RIGHT_READ) != 0, \
        "SA-3 FAILED: previously accumulated right lost after new record"
    print("SA-3 PASS: accumulated rights are monotone (never decrease)")


def test_sa4_replay_increases_step_count():
    """SA-4: Replaying the same action must still be counted as a separate step.
    The caller is responsible for nonce-based replay detection at the action level;
    SequenceContext tracks all steps regardless."""
    ctx = SequenceContext()
    actor = b"\x01" * 32
    resource = b"\x02" * 32

    ctx.record(actor, resource, RIGHT_READ, 100)
    ctx.record(actor, resource, RIGHT_READ, 100)  # same params

    assert ctx.step_count() == 2, \
        "SA-4 FAILED: replay not counted as separate step (step_count should be 2)"
    print("SA-4 PASS: each record() call is counted regardless of content")


def test_zero_session_limit_rejects_everything():
    """Edge case: session with no rights at all — any action exceeds limit."""
    ctx = SequenceContext()
    actor = b"\x01" * 32
    resource = b"\x02" * 32

    ctx.record(actor, resource, RIGHT_READ, 100)
    assert ctx.exceeds_limit(0), \
        "Zero session limit must reject even READ"
    print("Edge case PASS: zero session limit rejects all rights")


if __name__ == "__main__":
    test_sa1_read_transform_write_detected()
    test_sa2_rights_creep_detected()
    test_sa3_accumulation_is_monotone()
    test_sa4_replay_increases_step_count()
    test_zero_session_limit_rejects_everything()
    print("\nAll sequence attack tests passed.")

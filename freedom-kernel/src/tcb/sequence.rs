/// Composition safety engine — closes the "local safety ≠ global safety" gap.
///
/// A kernel that verifies each action independently can be exploited by composing
/// individually-permitted actions into a globally-harmful sequence:
///   READ (permitted) → TRANSFORM (permitted) → WRITE (permitted)
///   → net effect: copy-and-modify, which may violate a global policy.
///
/// `SequenceContext` tracks accumulated rights within a session. The caller
/// gates new actions against the accumulated state, enforcing that the combined
/// effect of a sequence of actions remains within declared session limits.
///
/// # Design constraint
/// This module contains no policy logic. Policy (what the accumulated limit should be)
/// is the caller's responsibility. This module tracks facts about what has happened.
#![forbid(unsafe_code)]

#[cfg(feature = "embedded")]
use alloc::vec::Vec;
#[cfg(not(feature = "embedded"))]
use std::vec::Vec;

use crate::tcb::types::{Bytes32, Rights};

/// One record of a permitted action within a session.
#[derive(Debug, Clone)]
pub struct PermittedStep {
    /// Actor who took the action.
    pub actor_id: Bytes32,
    /// Resource that was accessed.
    pub resource_hash: Bytes32,
    /// Rights that were exercised.
    pub rights_used: Rights,
    /// Unix seconds when the action was verified.
    pub timestamp: u64,
}

/// Session-scoped composition tracker.
///
/// Create one per session. Call `record()` after each `Decision::Permit`.
/// Call `accumulated_rights()` before verifying the next action to check
/// whether the cumulative effect is still within session policy.
#[derive(Debug, Default)]
pub struct SequenceContext {
    steps: Vec<PermittedStep>,
    /// Bitwise union of all rights exercised so far in this session.
    accumulated: Rights,
}

impl SequenceContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a permitted action. Called by the orchestration layer after
    /// `verify()` returns `Decision::Permit`.
    pub fn record(&mut self, actor_id: Bytes32, resource_hash: Bytes32, rights_used: Rights, now: u64) {
        self.accumulated |= rights_used;
        self.steps.push(PermittedStep { actor_id, resource_hash, rights_used, timestamp: now });
    }

    /// Bitmask of all rights exercised so far in this session.
    /// Policy layer compares this against the session's declared limit.
    pub fn accumulated_rights(&self) -> Rights {
        self.accumulated
    }

    /// Number of steps recorded.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Returns true if the accumulated rights exceed the session limit.
    /// `session_limit` is the maximum rights allowed for this session.
    pub fn exceeds_limit(&self, session_limit: Rights) -> bool {
        (self.accumulated & !session_limit) != 0
    }

    /// Snapshot of all recorded steps (for audit / forensics).
    pub fn steps(&self) -> &[PermittedStep] {
        &self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcb::types::{RIGHT_READ, RIGHT_WRITE};

    #[test]
    fn accumulates_rights_correctly() {
        let mut ctx = SequenceContext::new();
        ctx.record([1u8; 32], [2u8; 32], RIGHT_READ, 100);
        assert_eq!(ctx.accumulated_rights(), RIGHT_READ);
        ctx.record([1u8; 32], [2u8; 32], RIGHT_WRITE, 101);
        assert_eq!(ctx.accumulated_rights(), RIGHT_READ | RIGHT_WRITE);
    }

    #[test]
    fn exceeds_limit_detected() {
        let mut ctx = SequenceContext::new();
        ctx.record([1u8; 32], [2u8; 32], RIGHT_READ, 100);
        assert!(!ctx.exceeds_limit(RIGHT_READ | RIGHT_WRITE));
        ctx.record([1u8; 32], [2u8; 32], RIGHT_WRITE, 101);
        // Session was declared read-only
        assert!(ctx.exceeds_limit(RIGHT_READ));
    }
}

// ─── Kani harnesses — L-1 fix: composition safety model-checked ──────────────
// Build: cargo kani --harness prop_seq_accumulated_monotone
#[allow(unexpected_cfgs)]
#[cfg(kani)]
mod kani_harnesses {
    use super::*;
    use crate::tcb::types::Rights;

    /// INV-SEQ-1: accumulated_rights is monotonic (high-water mark property).
    /// Once a right has been accumulated, it cannot be removed by recording another step.
    #[kani::proof]
    fn prop_seq_accumulated_monotone() {
        let r1: Rights = kani::any();
        let r2: Rights = kani::any();
        let now1: u64 = kani::any();
        let now2: u64 = kani::any();
        let actor = [1u8; 32];
        let resource = [2u8; 32];

        let mut ctx = SequenceContext::new();
        ctx.record(actor, resource, r1, now1);
        let after_first = ctx.accumulated_rights();

        ctx.record(actor, resource, r2, now2);
        let after_second = ctx.accumulated_rights();

        // Monotone: every bit set after first remains set after second.
        assert!((after_first & after_second) == after_first);
        // Specifically: union of both inputs.
        assert!(after_second == (r1 | r2));
    }

    /// INV-SEQ-2: exceeds_limit is consistent with accumulated_rights.
    /// (accumulated & !limit) != 0  ↔  exceeds_limit returns true.
    #[kani::proof]
    fn prop_seq_exceeds_limit_consistent() {
        let r: Rights = kani::any();
        let limit: Rights = kani::any();
        let now: u64 = kani::any();
        let actor = [3u8; 32];
        let resource = [4u8; 32];

        let mut ctx = SequenceContext::new();
        ctx.record(actor, resource, r, now);

        let exceeds = ctx.exceeds_limit(limit);
        let expected = (r & !limit) != 0;
        assert!(exceeds == expected);
    }

    /// INV-SEQ-3: step_count equals number of record() calls.
    /// Recording N times produces step_count == N (up to bounded N).
    #[kani::proof]
    #[kani::unwind(5)]
    fn prop_seq_step_count_matches_records() {
        let actor = [5u8; 32];
        let resource = [6u8; 32];
        let r: Rights = kani::any();
        let now: u64 = kani::any();

        let mut ctx = SequenceContext::new();
        let n: u8 = kani::any();
        kani::assume(n <= 4);

        for _ in 0..n {
            ctx.record(actor, resource, r, now);
        }
        assert!(ctx.step_count() == n as usize);
    }

    /// INV-SEQ-4: an empty session never exceeds any limit (vacuous truth).
    #[kani::proof]
    fn prop_seq_empty_never_exceeds() {
        let limit: Rights = kani::any();
        let ctx = SequenceContext::new();
        assert!(!ctx.exceeds_limit(limit));
        assert!(ctx.accumulated_rights() == 0);
        assert!(ctx.step_count() == 0);
    }

    /// INV-SEQ-5: idempotent record — recording the same rights twice
    /// does not change accumulated_rights but increases step_count.
    #[kani::proof]
    fn prop_seq_idempotent_rights() {
        let r: Rights = kani::any();
        let now: u64 = kani::any();
        let actor = [7u8; 32];
        let resource = [8u8; 32];

        let mut ctx = SequenceContext::new();
        ctx.record(actor, resource, r, now);
        let acc1 = ctx.accumulated_rights();
        ctx.record(actor, resource, r, now);
        let acc2 = ctx.accumulated_rights();

        // Rights bitmask unchanged (idempotent under bitwise OR with self).
        assert!(acc1 == acc2);
        // But step count increased.
        assert!(ctx.step_count() == 2);
    }
}

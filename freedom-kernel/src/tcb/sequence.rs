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

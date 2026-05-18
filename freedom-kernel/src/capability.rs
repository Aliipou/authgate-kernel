//! Capability algebra — the closed, finite vocabulary of authority operations.
//!
//! # Hard constraints (enforced by CI)
//!
//! This file must stay:
//! - **Finite** — all variants are enumerated at compile time; no open extension points
//! - **Closed** — exhaustive enums only; no trait objects, no dynamic dispatch
//! - **Algebraic** — pure data (enums + Copy); no logic, no state, no side effects
//! - **Self-contained** — zero project imports (`use crate::` is forbidden here)
//! - **Small** — hard ceiling of 150 LOC (CI-enforced)
//!
//! # What this file must never become
//!
//! - A policy DSL (no evaluation, no rule matching)
//! - A semantic interpreter (no string analysis, no NLP, no heuristics)
//! - A contextual reasoner (no runtime state, no environment queries)
//! - A plugin system (no trait impls for external types, no open variants)
//!
//! The only permitted impls are `Display` and boundary-only `from_str` for `Operation`.
//! Every other behavior belongs outside this file.

/// The exhaustive set of capability kinds this kernel recognizes.
///
/// Extending this enum requires updating the verifier. There is no catch-all variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    Read,
    Write,
    Delegate,
    Spawn,
    IPCSend,
    IPCReceive,
    ConsumeQuota,
    EnterDomain,
}

/// Operations that can be checked against a `RightsClaim`.
///
/// This is a subset of `CapabilityKind`: the three operations that claims model today.
/// All internal code must use this enum. String conversion is only permitted at
/// external boundaries (C ABI, Python API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Delegate,
}

impl Operation {
    /// Parse from string — only for external boundaries (C ABI, Python API).
    /// Internal Rust code must use the enum variant directly.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Operation::Read),
            "write" => Some(Operation::Write),
            "delegate" => Some(Operation::Delegate),
            _ => None,
        }
    }
}

impl core::fmt::Display for Operation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Operation::Read => f.write_str("read"),
            Operation::Write => f.write_str("write"),
            Operation::Delegate => f.write_str("delegate"),
        }
    }
}

/// How authority transfers between agents.
///
/// Must be chosen explicitly when designing delegation flows — no implicit default.
///
/// ```text
/// child_capability ⊆ parent_capability   (attenuation invariant)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOp {
    /// Temporary subset — delegator retains authority.
    Delegate,
    /// Ownership move — delegator loses authority.
    Transfer,
    /// Weaker capability — strictly fewer permissions than source.
    Attenuate,
    /// Duplicate authority — both hold equivalent claims (use with caution).
    Clone,
    /// Time-bound delegation — expires automatically; equivalent to Delegate + expiry.
    Lease,
    /// Invalidate — removes the capability from the holder.
    Revoke,
}

/// Revocation strategy. Must be chosen explicitly; there is no safe default.
///
/// Tradeoffs:
/// - `Eager`: strong consistency, higher latency, more coordination
/// - `Lazy`: lower latency, brief window of stale access after revocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationModel {
    /// All holders are notified immediately. Revocation is atomic.
    Eager,
    /// Revocation propagates on next use. Simpler to implement; weaker guarantee.
    Lazy,
}

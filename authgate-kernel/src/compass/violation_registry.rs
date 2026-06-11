#![forbid(unsafe_code)]
//! Violation registry — bookkeeping input for the Mahdavi Compass.
//!
//! NOT in the TCB. Post-hoc scorer — annotates, never denies.
//! The deny threshold is operator policy, not theory.
//!
//! Records observed rights violations so the Compass can compute the
//! "rights violations decrease" (RVD) dimension from before/after counts.
//! Recording or resolving an entry has no enforcement effect whatsoever.

/// Kind of rights violation observed (post hoc) on a victim's resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    /// Control exercised over a resource without an authorizing capability.
    UnauthorizedControl,
    /// Action affecting a party who never consented.
    ConsentMissing,
    /// Consent obtained or action driven under coercion.
    CoercionDetected,
    /// An agent escalated authority beyond its delegated sovereignty.
    SovereigntyEscalation,
}

/// One observed violation. Identifiers are opaque 32-byte hashes, matching
/// the kernel's entity/resource id convention.
#[derive(Debug, Clone)]
pub struct ViolationEntry {
    pub violator: [u8; 32],
    pub victim: [u8; 32],
    pub resource: [u8; 32],
    pub violation_type: ViolationType,
    /// Unix timestamp (seconds) when the violation was detected.
    pub detected_at: u64,
    pub resolved: bool,
}

/// Append-only list of observed violations. Purely advisory bookkeeping:
/// the Compass reads counts from it; nothing in the kernel gates on it.
#[derive(Debug, Default)]
pub struct ViolationRegistry {
    entries: Vec<ViolationEntry>,
}

impl ViolationRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a newly observed violation.
    pub fn record(&mut self, entry: ViolationEntry) {
        self.entries.push(entry);
    }

    /// Mark the entry at `index` as resolved. Out-of-range indices are a
    /// no-op (advisory data; nothing security-relevant depends on it).
    pub fn resolve(&mut self, index: usize) {
        if let Some(entry) = self.entries.get_mut(index) {
            entry.resolved = true;
        }
    }

    /// Number of unresolved violations.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.resolved).count()
    }

    /// Total number of recorded violations, resolved or not.
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }
}

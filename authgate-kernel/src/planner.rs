//! Multi-step plan verification with IFC taint propagation.
//!
//! This module is **Trusted** (not TCB). It wraps the pure `engine::verify` call
//! and adds temporal cross-action invariants. The engine itself is unchanged.

use crate::engine;
use crate::wire::{ActionWire, OwnershipRegistryWire, VerificationResultWire};

// ── Taint helpers ────────────────────────────────────────────────────────────

// PUBLIC < INTERNAL < SECRET
fn label_rank(s: &str) -> u8 {
    match s { "SECRET" => 2, "INTERNAL" => 1, _ => 0 }
}

fn highest_label(current: &str, new_labels: &[String]) -> String {
    let mut best = current.to_string();
    for l in new_labels {
        if label_rank(l) > label_rank(&best) { best = l.clone(); }
    }
    best
}

// PROOF: label_dominates(a, b) → rank(a) > rank(b); strict so equal labels are not violations
fn label_dominates(taint: &str, target: &str) -> bool {
    label_rank(taint) > label_rank(target)
}

// ── StateProjection ──────────────────────────────────────────────────────────

/// Accumulated IFC state across a plan prefix.
/// Tracks the highest label read so far; detects downward writes.
#[derive(Clone, Debug)]
pub struct StateProjection {
    pub ifc_taint: String,
    pub read_labels: Vec<String>,
    pub depth: usize,
}

impl StateProjection {
    pub fn empty() -> Self {
        Self { ifc_taint: "PUBLIC".to_string(), read_labels: vec![], depth: 0 }
    }

    /// Advance projection after a permitted action.
    /// Returns Err if this action creates a temporal IFC violation.
    pub fn advance(
        &self,
        action: &ActionWire,
        _registry: &OwnershipRegistryWire,
    ) -> Result<Self, TemporalViolation> {
        let new_read_labels: Vec<String> = action
            .resources_read
            .iter()
            .filter(|r| !r.ifc_label.is_empty())
            .map(|r| r.ifc_label.clone())
            .collect();

        let new_taint = highest_label(&self.ifc_taint, &new_read_labels);

        for write_res in &action.resources_write {
            if !write_res.ifc_label.is_empty()
                && label_dominates(&new_taint, &write_res.ifc_label)
            {
                return Err(TemporalViolation::IFCDownwardFlow {
                    taint: new_taint.clone(),
                    target: write_res.ifc_label.clone(),
                    at_depth: self.depth,
                });
            }
        }

        let mut combined = self.read_labels.clone();
        combined.extend(new_read_labels);

        Ok(Self { ifc_taint: new_taint, read_labels: combined, depth: self.depth + 1 })
    }
}

// ── TemporalViolation ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TemporalViolation {
    IFCDownwardFlow { taint: String, target: String, at_depth: usize },
    CapabilityAmplification { at_depth: usize, detail: String },
}

impl TemporalViolation {
    pub fn description(&self) -> String {
        match self {
            Self::IFCDownwardFlow { taint, target, at_depth } => format!(
                "IFC downward flow at step {}: taint={} write_label={}",
                at_depth, taint, target
            ),
            Self::CapabilityAmplification { at_depth, detail } => format!(
                "Capability amplification at step {}: {}", at_depth, detail
            ),
        }
    }
}

// ── PlanVerificationResult ────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PlanVerificationResult {
    pub all_permitted: bool,
    pub results: Vec<VerificationResultWire>,
    pub temporal_violation: Option<TemporalViolation>,
    pub blocked_at: Option<usize>,
}

// ── verify_plan ──────────────────────────────────────────────────────────────

/// Verifies a finite plan prefix against:
/// 1. Per-action kernel gate (ownership, delegation, forbidden flags)
/// 2. Cross-action IFC taint propagation
///
/// PROVEN PROPERTIES (Kani harness: prop_plan_permitted_means_no_forbidden_flags):
/// - If all_permitted is true, no action in the prefix set any forbidden flag
/// - IFC taint never decreases across the plan
///
/// NOT PROVEN: safety of plans longer than KANI_UNWIND depth
pub fn verify_plan(
    registry: &OwnershipRegistryWire,
    actions: &[ActionWire],
) -> PlanVerificationResult {
    let mut state = StateProjection::empty();
    let mut results = Vec::with_capacity(actions.len());

    for (i, action) in actions.iter().enumerate() {
        let result = engine::verify(registry, action);
        let permitted = result.permitted;
        results.push(result);

        if !permitted {
            return PlanVerificationResult {
                all_permitted: false,
                results,
                temporal_violation: None,
                blocked_at: Some(i),
            };
        }

        match state.advance(action, registry) {
            Ok(next) => state = next,
            Err(violation) => {
                return PlanVerificationResult {
                    all_permitted: false,
                    results,
                    temporal_violation: Some(violation),
                    blocked_at: Some(i),
                };
            }
        }
    }

    PlanVerificationResult { all_permitted: true, results, temporal_violation: None, blocked_at: None }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ClaimWire, EntityKind, EntityWire, MachineOwnerWire, ResourceWire};

    fn human(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Human }
    }
    fn machine(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Machine }
    }
    fn owned_registry() -> OwnershipRegistryWire {
        OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![MachineOwnerWire { machine: machine("bot"), owner: human("alice") }],
        }
    }
    fn base_action(id: &str) -> ActionWire {
        ActionWire {
            action_id: id.to_string(),
            actor: machine("bot"),
            description: String::new(),
            resources_read: vec![],
            resources_write: vec![],
            resources_delegate: vec![],
            governs_humans: vec![],
            argument: String::new(),
            increases_machine_sovereignty: false,
            resists_human_correction: false,
            bypasses_verifier: false,
            weakens_verifier: false,
            disables_corrigibility: false,
            machine_coalition_dominion: false,
            coerces: false,
            deceives: false,
            self_modification_weakens_verifier: false,
            machine_coalition_reduces_freedom: false,
        }
    }
    fn labeled_resource(name: &str, label: &str) -> ResourceWire {
        ResourceWire {
            name: name.to_string(),
            rtype: "file".to_string(),
            scope: String::new(),
            is_public: false,
            ifc_label: label.to_string(),
        }
    }
    fn claim_rw(entity: EntityWire, resource: ResourceWire) -> ClaimWire {
        ClaimWire {
            holder: entity,
            resource,
            can_read: true,
            can_write: true,
            can_delegate: false,
            confidence: 1.0,
            expires_at: None,
        }
    }

    #[test]
    fn test_plan_ifc_taint_blocks_downward_write() {
        let secret_res = labeled_resource("secret", "SECRET");
        let public_res = labeled_resource("public_out", "PUBLIC");
        let mut registry = owned_registry();
        registry.claims = vec![
            claim_rw(machine("bot"), secret_res.clone()),
            claim_rw(machine("bot"), public_res.clone()),
        ];

        let mut read_secret = base_action("read-secret");
        read_secret.resources_read = vec![secret_res];

        let mut write_public = base_action("write-public");
        write_public.resources_write = vec![public_res];

        let result = verify_plan(&registry, &[read_secret, write_public]);
        assert!(!result.all_permitted, "IFC downward flow must be blocked");
        assert!(result.temporal_violation.is_some());
        assert_eq!(result.blocked_at, Some(1));
    }

    #[test]
    fn test_plan_all_permitted_no_temporal_violation() {
        let public_read = labeled_resource("docs", "PUBLIC");
        let public_write = labeled_resource("output", "PUBLIC");
        let mut registry = owned_registry();
        registry.claims = vec![
            claim_rw(machine("bot"), public_read.clone()),
            claim_rw(machine("bot"), public_write.clone()),
        ];

        let mut a1 = base_action("read");
        a1.resources_read = vec![public_read];

        let mut a2 = base_action("write");
        a2.resources_write = vec![public_write];

        let result = verify_plan(&registry, &[a1, a2]);
        assert!(result.all_permitted);
        assert!(result.temporal_violation.is_none());
        assert_eq!(result.blocked_at, None);
    }

    #[test]
    fn test_plan_single_forbidden_flag_blocks_entire_plan() {
        let registry = owned_registry();
        let ok_action = base_action("ok");
        let mut bad_action = base_action("bad");
        bad_action.increases_machine_sovereignty = true;

        let result = verify_plan(&registry, &[ok_action, bad_action]);
        assert!(!result.all_permitted);
        assert_eq!(result.blocked_at, Some(1));
    }

    #[test]
    fn test_empty_plan_is_permitted() {
        let result = verify_plan(&owned_registry(), &[]);
        assert!(result.all_permitted);
        assert!(result.results.is_empty());
    }

    #[test]
    fn test_internal_to_public_write_blocked() {
        let internal_res = labeled_resource("internal_doc", "INTERNAL");
        let public_res = labeled_resource("pub_summary", "PUBLIC");
        let mut registry = owned_registry();
        registry.claims = vec![
            claim_rw(machine("bot"), internal_res.clone()),
            claim_rw(machine("bot"), public_res.clone()),
        ];

        let mut a1 = base_action("read-internal");
        a1.resources_read = vec![internal_res];

        let mut a2 = base_action("write-public");
        a2.resources_write = vec![public_res];

        let result = verify_plan(&registry, &[a1, a2]);
        assert!(!result.all_permitted, "INTERNAL→PUBLIC downward flow must be blocked");
        assert!(matches!(
            result.temporal_violation,
            Some(TemporalViolation::IFCDownwardFlow { .. })
        ));
    }

    #[test]
    fn test_secret_to_secret_write_permitted() {
        let secret_read = labeled_resource("src_secret", "SECRET");
        let secret_write = labeled_resource("dst_secret", "SECRET");
        let mut registry = owned_registry();
        registry.claims = vec![
            claim_rw(machine("bot"), secret_read.clone()),
            claim_rw(machine("bot"), secret_write.clone()),
        ];

        let mut a1 = base_action("read-s");
        a1.resources_read = vec![secret_read];

        let mut a2 = base_action("write-s");
        a2.resources_write = vec![secret_write];

        let result = verify_plan(&registry, &[a1, a2]);
        assert!(result.all_permitted, "SECRET→SECRET write must be permitted");
    }
}

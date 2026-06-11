#![forbid(unsafe_code)]
//! Compass metric — `C(a) = w1*RVD + w2*VOI + w3*CD`.
//!
//! NOT in the TCB. Post-hoc scorer — annotates, never denies.
//! The deny threshold is operator policy, not theory.
//!
//! Each dimension is computed from observable before/after state. The score
//! and its annotation are pure data: nothing here returns a deny, blocks an
//! action, or carries a hardcoded blocking threshold. If an operator wants
//! to gate on the score, they bring their own threshold via
//! [`flagged_below`] and act on it in their own policy layer.

/// Weights for the three Compass dimensions. Defaults are equal (1/3 each).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompassWeights {
    pub w_rvd: f32,
    pub w_voi: f32,
    pub w_cd: f32,
}

impl Default for CompassWeights {
    fn default() -> Self {
        Self {
            w_rvd: 1.0 / 3.0,
            w_voi: 1.0 / 3.0,
            w_cd: 1.0 / 3.0,
        }
    }
}

/// Observable before/after state of the world surrounding an action.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompassInput {
    /// Active (unresolved) rights violations before the action.
    pub violations_before: u32,
    /// Active (unresolved) rights violations after the action.
    pub violations_after: u32,
    /// Voluntary contracts newly formed by the action.
    pub new_voluntary_contracts: u32,
    /// Normalization ceiling for voluntary contracts in this context.
    pub max_voluntary_contracts: u32,
    /// Irreversibility of the system state before the action, in [0, 1].
    pub irreversibility_before: f32,
    /// Irreversibility of the system state after the action, in [0, 1].
    pub irreversibility_after: f32,
}

/// RVD — rights violations decrease.
///
/// `(before - after) / (before + 1)`. Range is roughly `[-N, +1)`:
/// approaches +1 when many violations are all resolved, is 0 when nothing
/// changes, and goes arbitrarily negative as an action *creates* violations
/// (e.g. before=0, after=N gives -N).
pub fn rights_violations_decrease(before: u32, after: u32) -> f32 {
    (before as f32 - after as f32) / (before as f32 + 1.0)
}

/// VOI — voluntary order increases.
///
/// `new / max`, clamped into [0, 1]. A `max` of 0 means no voluntary order
/// was possible in this context, so the dimension contributes 0.
pub fn voluntary_order_increases(new: u32, max: u32) -> f32 {
    if max == 0 {
        return 0.0;
    }
    (new as f32 / max as f32).clamp(0.0, 1.0)
}

/// CD — coercion decreases.
///
/// `(irrev_before - irrev_after)` clamped to [-1, +1]: positive when the
/// action made the system more reversible (less coercive lock-in), negative
/// when it made things harder to undo.
pub fn coercion_decreases(irrev_before: f32, irrev_after: f32) -> f32 {
    (irrev_before - irrev_after).clamp(-1.0, 1.0)
}

/// Composite Compass score plus its per-dimension breakdown.
///
/// `compass_negative` is an annotation, not a verdict: it says the action
/// moved the world away from freedom along these axes. What (if anything)
/// to do about that is operator policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompassScore {
    pub score: f32,
    pub rvd: f32,
    pub voi: f32,
    pub cd: f32,
    pub compass_negative: bool,
}

/// Compute `C(a) = w1*RVD + w2*VOI + w3*CD` for an action's observed effects.
pub fn score(input: &CompassInput, weights: &CompassWeights) -> CompassScore {
    let rvd = rights_violations_decrease(input.violations_before, input.violations_after);
    let voi =
        voluntary_order_increases(input.new_voluntary_contracts, input.max_voluntary_contracts);
    let cd = coercion_decreases(input.irreversibility_before, input.irreversibility_after);
    let score = weights.w_rvd * rvd + weights.w_voi * voi + weights.w_cd * cd;
    CompassScore {
        score,
        rvd,
        voi,
        cd,
        compass_negative: score < 0.0,
    }
}

/// Human-readable guidance attached to an action record. Advisory only:
/// it never carries, implies, or triggers a deny.
#[derive(Debug, Clone, PartialEq)]
pub struct GuidanceAnnotation {
    pub compass_score: f32,
    pub compass_negative: bool,
    pub guidance_reason: String,
}

/// Turn a [`CompassScore`] into a guidance annotation. This is the only
/// output the Compass produces about an action — a description, never a
/// decision.
pub fn annotate(score: &CompassScore) -> GuidanceAnnotation {
    let direction = if score.compass_negative {
        "moved away from freedom"
    } else {
        "moved toward (or stayed neutral on) freedom"
    };
    GuidanceAnnotation {
        compass_score: score.score,
        compass_negative: score.compass_negative,
        guidance_reason: format!(
            "Compass score {:.3}: action {} (rights-violation change {:.3}, \
             voluntary-order gain {:.3}, coercion change {:.3}). Advisory only; \
             no enforcement implied.",
            score.score, direction, score.rvd, score.voi, score.cd
        ),
    }
}

/// Advisory only. Returns whether the score falls below a threshold the
/// OPERATOR chose — the theory ships no threshold and never denies. What a
/// `true` here means (log, review, deny) is entirely the operator's policy.
pub fn flagged_below(score: &CompassScore, operator_threshold: f32) -> bool {
    score.score < operator_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compass::violation_registry::{ViolationEntry, ViolationRegistry, ViolationType};

    fn entry() -> ViolationEntry {
        ViolationEntry {
            violator: [1u8; 32],
            victim: [2u8; 32],
            resource: [3u8; 32],
            violation_type: ViolationType::UnauthorizedControl,
            detected_at: 1_750_000_000,
            resolved: false,
        }
    }

    #[test]
    fn compass_positive_action_scores_above_zero() {
        // Violations drop 4 -> 1, contracts up, irreversibility down.
        let input = CompassInput {
            violations_before: 4,
            violations_after: 1,
            new_voluntary_contracts: 3,
            max_voluntary_contracts: 4,
            irreversibility_before: 0.8,
            irreversibility_after: 0.2,
        };
        let s = score(&input, &CompassWeights::default());
        assert!(s.score > 0.0);
        assert!(!s.compass_negative);
        assert!(s.rvd > 0.0);
        assert!(s.voi > 0.0);
        assert!(s.cd > 0.0);
    }

    #[test]
    fn compass_negative_action_scores_below_zero() {
        // Violations created, no contracts, irreversibility increased.
        let input = CompassInput {
            violations_before: 0,
            violations_after: 3,
            new_voluntary_contracts: 0,
            max_voluntary_contracts: 5,
            irreversibility_before: 0.1,
            irreversibility_after: 0.9,
        };
        let s = score(&input, &CompassWeights::default());
        assert!(s.score < 0.0);
        assert!(s.compass_negative);
    }

    #[test]
    fn rvd_with_zero_before_penalizes_new_violations() {
        // before=0, after=2 -> (0 - 2) / (0 + 1) = -2.0
        assert_eq!(rights_violations_decrease(0, 2), -2.0);
        // before=0, after=0 -> no change, no credit.
        assert_eq!(rights_violations_decrease(0, 0), 0.0);
    }

    #[test]
    fn voi_with_zero_max_is_zero() {
        assert_eq!(voluntary_order_increases(7, 0), 0.0);
        assert_eq!(voluntary_order_increases(0, 0), 0.0);
    }

    #[test]
    fn voi_stays_in_unit_interval() {
        assert_eq!(voluntary_order_increases(10, 5), 1.0); // over-cap clamps
        assert_eq!(voluntary_order_increases(2, 4), 0.5);
        assert_eq!(voluntary_order_increases(0, 4), 0.0);
    }

    #[test]
    fn cd_clamps_to_unit_band() {
        assert_eq!(coercion_decreases(5.0, 0.0), 1.0);
        assert_eq!(coercion_decreases(0.0, 5.0), -1.0);
        let mid = coercion_decreases(0.6, 0.4);
        assert!((mid - 0.2).abs() < 1e-6);
    }

    #[test]
    fn custom_weights_change_the_composite() {
        let input = CompassInput {
            violations_before: 0,
            violations_after: 0,
            new_voluntary_contracts: 1,
            max_voluntary_contracts: 1,
            irreversibility_before: 0.0,
            irreversibility_after: 0.0,
        };
        // Only VOI is nonzero (=1.0); weight it fully.
        let w = CompassWeights {
            w_rvd: 0.0,
            w_voi: 1.0,
            w_cd: 0.0,
        };
        let s = score(&input, &w);
        assert!((s.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn violation_registry_active_count_tracks_record_and_resolve() {
        let mut reg = ViolationRegistry::new();
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.total_count(), 0);

        reg.record(entry());
        reg.record(entry());
        assert_eq!(reg.active_count(), 2);
        assert_eq!(reg.total_count(), 2);

        reg.resolve(0);
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.total_count(), 2); // resolution never erases history

        reg.resolve(99); // out of range: advisory no-op
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn annotate_never_denies_only_describes() {
        let bad = CompassInput {
            violations_before: 0,
            violations_after: 10,
            new_voluntary_contracts: 0,
            max_voluntary_contracts: 1,
            irreversibility_before: 0.0,
            irreversibility_after: 1.0,
        };
        let s = score(&bad, &CompassWeights::default());
        let ann = annotate(&s);
        // Even for a strongly compass-negative action the output is a
        // description, not a verdict: it flags negativity and explains why.
        assert!(ann.compass_negative);
        assert!(ann.compass_score < 0.0);
        assert!(ann.guidance_reason.contains("Advisory only"));
        assert!(!ann.guidance_reason.to_lowercase().contains("denied"));
    }

    #[test]
    fn flagged_below_respects_operator_threshold() {
        let s = CompassScore {
            score: -0.25,
            rvd: -1.0,
            voi: 0.0,
            cd: 0.25,
            compass_negative: true,
        };
        // Strict operator flags it; lenient operator does not. Same score,
        // different policy — the threshold lives with the operator.
        assert!(flagged_below(&s, 0.0));
        assert!(!flagged_below(&s, -0.5));
        // Boundary: score == threshold is not "below".
        assert!(!flagged_below(&s, -0.25));
    }
}

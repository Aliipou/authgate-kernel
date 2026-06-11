//! Red-team suite for the Mahdavi Compass (GAP 3 / axiom A7).
//!
//! The central SAFETY PROPERTY proven here: the Compass NEVER denies. It only
//! scores and annotates. The only "blocking-ish" function, `flagged_below`,
//! requires an OPERATOR-supplied threshold — the theory ships none. These
//! tests attack the scorer (gaming, degenerate/NaN inputs, weight abuse,
//! registry poisoning) and assert it stays total and non-blocking.

#![cfg(test)]

use crate::compass::metric::{
    annotate, coercion_decreases, flagged_below, rights_violations_decrease, score,
    voluntary_order_increases, CompassInput, CompassScore, CompassWeights,
};
use crate::compass::violation_registry::{ViolationEntry, ViolationRegistry, ViolationType};

fn input(vb: u32, va: u32, nc: u32, mc: u32, ib: f32, ia: f32) -> CompassInput {
    CompassInput {
        violations_before: vb,
        violations_after: va,
        new_voluntary_contracts: nc,
        max_voluntary_contracts: mc,
        irreversibility_before: ib,
        irreversibility_after: ia,
    }
}

fn entry(resolved: bool) -> ViolationEntry {
    ViolationEntry {
        violator: [1u8; 32],
        victim: [2u8; 32],
        resource: [3u8; 32],
        violation_type: ViolationType::UnauthorizedControl,
        detected_at: 1_750_000_000,
        resolved,
    }
}

// ── 1. Score-gaming: inflating voluntary contracts cannot mask new violations
#[test]
fn attack_inflate_contracts_cannot_hide_rising_violations() {
    // Violations explode 0 -> 8 (RVD = -8), contracts maxed (VOI = 1), no
    // coercion change (CD = 0). Default equal weights:
    //   score = (-8 + 1 + 0) / 3 ≈ -2.33  → still strongly negative.
    let s = score(&input(0, 8, 9, 9, 0.5, 0.5), &CompassWeights::default());
    assert!(s.score < 0.0, "gamed score should stay negative, got {}", s.score);
    assert!(s.compass_negative);
    assert!(s.rvd <= -7.0); // the violation term dominates
}

// ── 2/3. RVD edge cases around before == 0 ──────────────────────────────────
#[test]
fn attack_rvd_zero_before_no_div_by_zero() {
    assert_eq!(rights_violations_decrease(0, 0), 0.0);
    assert_eq!(rights_violations_decrease(0, 5), -5.0);
    assert!(rights_violations_decrease(10, 0).is_finite());
}

// ── 4. VOI: new exceeds max → clamped to 1.0; max == 0 → 0.0 ────────────────
#[test]
fn attack_voi_clamped_and_zero_max_safe() {
    assert_eq!(voluntary_order_increases(100, 1), 1.0);
    assert_eq!(voluntary_order_increases(7, 0), 0.0);
    assert_eq!(voluntary_order_increases(0, 0), 0.0);
}

// ── 5. CD clamps extreme irreversibility deltas to [-1, 1] ──────────────────
#[test]
fn attack_cd_clamps_extremes() {
    assert_eq!(coercion_decreases(1000.0, 0.0), 1.0);
    assert_eq!(coercion_decreases(0.0, 1000.0), -1.0);
    assert_eq!(coercion_decreases(-50.0, 50.0), -1.0);
}

// ── 6. NaN / Inf inputs do not panic; NaN propagates honestly ───────────────
#[test]
fn attack_nan_input_produces_nan_score_no_panic() {
    let s = score(&input(1, 1, 1, 1, 0.0, f32::NAN), &CompassWeights::default());
    // CD becomes NaN; the composite is NaN. `NaN < 0.0` is false, so the
    // action is NOT mislabelled compass_negative. No panic — that's the point.
    assert!(s.cd.is_nan());
    assert!(s.score.is_nan());
    assert!(!s.compass_negative);
}

// ── 7. Zero weights → score 0, not negative ─────────────────────────────────
#[test]
fn attack_zero_weights_score_is_zero() {
    let w = CompassWeights { w_rvd: 0.0, w_voi: 0.0, w_cd: 0.0 };
    let s = score(&input(10, 0, 0, 0, 0.9, 0.1), &w);
    assert_eq!(s.score, 0.0);
    assert!(!s.compass_negative);
}

// ── 8. Negative weights are honored (validation is operator policy) ─────────
#[test]
fn attack_negative_weights_no_panic() {
    let w = CompassWeights { w_rvd: -1.0, w_voi: -1.0, w_cd: -1.0 };
    let s = score(&input(5, 0, 1, 1, 0.8, 0.2), &w);
    // No panic; arithmetic is exactly as defined. Sign flips because weights
    // are negative — weight sanity is the operator's responsibility, not the
    // theory's, and we assert the value rather than pretend it's guarded.
    assert!(s.score.is_finite());
}

// ── 9. Huge weights stay finite (no overflow panic) ─────────────────────────
#[test]
fn attack_huge_weights_finite() {
    let w = CompassWeights { w_rvd: 1.0e6, w_voi: 1.0e6, w_cd: 1.0e6 };
    let s = score(&input(2, 0, 1, 4, 0.5, 0.5), &w);
    assert!(s.score.is_finite());
}

// ── 10. annotate() only ever describes — never denies ───────────────────────
#[test]
fn attack_annotate_never_denies() {
    let worst = score(&input(0, 50, 0, 1, 0.0, 1.0), &CompassWeights::default());
    let ann = annotate(&worst);
    assert!(ann.compass_negative);
    assert!(ann.guidance_reason.to_lowercase().contains("advisory"));
    assert!(!ann.guidance_reason.to_lowercase().contains("deny"));
    assert!(!ann.guidance_reason.to_lowercase().contains("blocked"));
}

// ── 11. flagged_below is pure operator policy; theory ships no threshold ────
#[test]
fn attack_flagged_below_is_operator_policy_only() {
    let s = CompassScore { score: -0.3, rvd: -1.0, voi: 0.0, cd: 0.1, compass_negative: true };
    // A strict operator flags; a lenient one does not. With NEG_INFINITY (i.e.
    // "never deny"), nothing is ever flagged — proving there is no built-in
    // deny baked into the Compass.
    assert!(flagged_below(&s, 0.0));
    assert!(!flagged_below(&s, -1.0));
    assert!(!flagged_below(&s, f32::NEG_INFINITY));
    // Even a very compass-negative score is not flagged unless the operator
    // sets a threshold above it.
    let awful = CompassScore { score: -100.0, rvd: -100.0, voi: 0.0, cd: 0.0, compass_negative: true };
    assert!(!flagged_below(&awful, f32::NEG_INFINITY));
}

// ── 12. Registry: out-of-range resolve is a no-op ───────────────────────────
#[test]
fn attack_registry_resolve_out_of_range_noop() {
    let mut reg = ViolationRegistry::new();
    reg.record(entry(false));
    reg.resolve(9999); // no panic, no effect
    assert_eq!(reg.active_count(), 1);
    assert_eq!(reg.total_count(), 1);
}

// ── 13. Registry: active_count is monotone under record/resolve ─────────────
#[test]
fn attack_registry_active_count_monotonic() {
    let mut reg = ViolationRegistry::new();
    for _ in 0..5 {
        reg.record(entry(false));
    }
    assert_eq!(reg.active_count(), 5);
    reg.resolve(0);
    reg.resolve(1);
    assert_eq!(reg.active_count(), 3);
    assert_eq!(reg.total_count(), 5); // history never shrinks
}

// ── 14. Registry: double-resolve cannot drive the count negative ────────────
#[test]
fn attack_registry_double_resolve_safe() {
    let mut reg = ViolationRegistry::new();
    reg.record(entry(false));
    reg.resolve(0);
    reg.resolve(0); // idempotent
    assert_eq!(reg.active_count(), 0);
    assert_eq!(reg.total_count(), 1);
}

// ── 15. Property loop: finite inputs → finite score; never flagged at -inf ──
#[test]
fn attack_property_total_and_non_blocking() {
    let befores = [0u32, 1, 5, 100];
    let afters = [0u32, 1, 5, 100];
    let contracts = [0u32, 3, 10];
    let maxes = [0u32, 1, 5];
    let irrev = [0.0f32, 0.5, 1.0];
    let mut count = 0u32;
    for &vb in &befores {
        for &va in &afters {
            for &nc in &contracts {
                for &mc in &maxes {
                    for &ib in &irrev {
                        for &ia in &irrev {
                            let s = score(&input(vb, va, nc, mc, ib, ia), &CompassWeights::default());
                            assert!(s.score.is_finite(), "non-finite score for finite input");
                            assert_eq!(s.compass_negative, s.score < 0.0);
                            // SAFETY: with a "never deny" threshold nothing is flagged.
                            assert!(!flagged_below(&s, f32::NEG_INFINITY));
                            count += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(count >= 50, "property corpus too small: {count}");
}

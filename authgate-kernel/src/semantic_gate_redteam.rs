//! Red-team suite for the SemanticGate / CoercionAnalyzer (GAP 2 / A4-A5).
//!
//! These tests probe the heuristic detector adversarially. Because the gate
//! is explicitly advisory (NOT in the TCB, never structurally denies), the
//! goals are: (1) it catches the obvious coercion/deception patterns, (2) it
//! is *total* — never panics, confidence always finite and in [0,1], and
//! (3) its KNOWN evasions are documented honestly rather than hidden.

#![cfg(test)]

use crate::semantic_gate::{CoercionAnalyzer, SemanticAction, SemanticGate, SemanticVerdict};

fn base(description: &str) -> SemanticAction {
    SemanticAction {
        actor: "agent".to_string(),
        resource: "res".to_string(),
        description: description.to_string(),
        reversible: true,
        dependency_shares: vec![],
        removes_grantor_revocation: false,
    }
}

fn confidence_of(v: &SemanticVerdict) -> Option<f32> {
    match v {
        SemanticVerdict::Clean => None,
        SemanticVerdict::Coercion { confidence, .. }
        | SemanticVerdict::Deception { confidence, .. }
        | SemanticVerdict::Manipulation { confidence, .. } => Some(*confidence),
    }
}

// ── 1. Exit-blocking wins even when dressed up as benign + reversible ───────
#[test]
fn attack_exit_block_disguised_as_reversible_benign() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("routine settings update");
    a.reversible = true;
    a.removes_grantor_revocation = true;
    assert!(matches!(gate.check(&a), SemanticVerdict::Coercion { confidence, .. } if confidence == 1.0));
}

// ── 2/3/4. HHI threshold boundary (strict >) ────────────────────────────────
#[test]
fn attack_hhi_just_below_threshold_is_clean() {
    let gate = CoercionAnalyzer { hhi_threshold: 0.5, deception_markers: vec![] };
    let mut a = base("balanced");
    a.dependency_shares = vec![0.4999_f64.sqrt(), 0.0]; // HHI ≈ 0.4999
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

#[test]
fn attack_hhi_exactly_at_threshold_is_clean() {
    let gate = CoercionAnalyzer { hhi_threshold: 0.5, deception_markers: vec![] };
    let mut a = base("equal split");
    a.dependency_shares = vec![0.5, 0.5]; // HHI = 0.25 + 0.25 = 0.5 exactly
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

#[test]
fn attack_hhi_just_above_threshold_is_flagged() {
    let gate = CoercionAnalyzer { hhi_threshold: 0.5, deception_markers: vec![] };
    let mut a = base("concentrated");
    a.dependency_shares = vec![0.72, 0.1]; // HHI ≈ 0.5284
    assert!(matches!(gate.check(&a), SemanticVerdict::Manipulation { .. }));
}

// ── 5. Deception markers are case-insensitive ───────────────────────────────
#[test]
fn attack_deception_uppercase_detected() {
    let gate = CoercionAnalyzer::new();
    let a = base("MISLEAD the reviewer about scope");
    assert!(matches!(gate.check(&a), SemanticVerdict::Deception { .. }));
}

// ── 6. Substring matching is over-broad — a KNOWN false-positive surface ────
#[test]
fn attack_marker_embedded_in_word_false_positive_documented() {
    let gate = CoercionAnalyzer::new();
    // "shideaway" contains the substring "hide" → flagged, though innocuous.
    // Documented limitation of crude substring matching; a real classifier
    // (swapped in via the trait) would not over-trigger here.
    let a = base("move it to the shideaway folder");
    assert!(matches!(gate.check(&a), SemanticVerdict::Deception { .. }));
}

// ── 7. Unicode homoglyph EVADES the ASCII substring scan — documented ───────
#[test]
fn attack_unicode_homoglyph_evades_documented() {
    let gate = CoercionAnalyzer::new();
    // "hіde": the 'і' is Cyrillic U+0456, so ASCII "hide" is not a substring.
    // This evades detection — an honest limitation of substring heuristics.
    let a = base("h\u{0456}de the change from the log");
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

// ── 8. Empty dependency shares: no panic, no division, Clean ────────────────
#[test]
fn attack_empty_shares_no_panic() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("standalone");
    a.reversible = false; // irreversibility alone must not flag
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

// ── 9. Single total dependency: HHI = 1.0, confidence capped at 0.99 ────────
#[test]
fn attack_single_total_dependency_capped() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("route everything through actor");
    a.dependency_shares = vec![1.0];
    let v = gate.check(&a);
    assert!(matches!(v, SemanticVerdict::Manipulation { .. }));
    assert!(confidence_of(&v).unwrap() <= 0.99);
}

// ── 10. Shares summing > 1 (malformed input): no panic, still bounded ───────
#[test]
fn attack_shares_sum_exceeds_one_no_panic() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("garbage shares");
    a.dependency_shares = vec![0.9, 0.9, 0.9]; // HHI = 2.43
    let v = gate.check(&a);
    let c = confidence_of(&v).unwrap();
    assert!(c.is_finite() && (0.0..=1.0).contains(&c));
}

// ── 11. NaN share: comparison is false → falls through to Clean, no panic ───
#[test]
fn attack_nan_share_does_not_panic() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("nan poison");
    a.dependency_shares = vec![f64::NAN];
    // hhi == NaN; `NaN > threshold` is false, so it cannot trigger the HHI
    // branch and returns Clean. The point is totality: no panic.
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

// ── 12. Negative share squared is positive → can still flag, no panic ───────
#[test]
fn attack_negative_share_squares_positive() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("signed shares");
    a.dependency_shares = vec![-0.8]; // square = 0.64 > 0.5
    assert!(matches!(gate.check(&a), SemanticVerdict::Manipulation { .. }));
}

// ── 13. Totality + bounded-confidence over a large adversarial corpus ───────
#[test]
fn attack_totality_confidence_always_bounded() {
    let gate = CoercionAnalyzer::new();
    let descriptions = [
        "", "hide", "CONCEAL", "ordinary task", "disguise as routine",
        "h\u{0456}de", "shideaway", "pretend nothing happened",
    ];
    let share_sets: [Vec<f64>; 6] = [
        vec![],
        vec![1.0],
        vec![0.9, 0.9, 0.9],
        vec![f64::NAN],
        vec![-0.8],
        vec![0.3, 0.3, 0.3, 0.1],
    ];
    let mut count = 0u32;
    for d in &descriptions {
        for shares in &share_sets {
            for &rev in &[true, false] {
                for &exit in &[true, false] {
                    let a = SemanticAction {
                        actor: "a".into(),
                        resource: "r".into(),
                        description: (*d).to_string(),
                        reversible: rev,
                        dependency_shares: shares.clone(),
                        removes_grantor_revocation: exit,
                    };
                    let v = gate.check(&a); // must never panic
                    if let Some(c) = confidence_of(&v) {
                        assert!(c.is_finite(), "confidence not finite for {a:?}");
                        assert!((0.0..=1.0).contains(&c), "confidence {c} out of [0,1] for {a:?}");
                    }
                    count += 1;
                }
            }
        }
    }
    assert!(count >= 50, "corpus too small: {count}");
}

// ── 14. Irreversibility ALONE is not flagged (documented design choice) ─────
#[test]
fn attack_irreversibility_alone_not_flagged() {
    let gate = CoercionAnalyzer::new();
    let mut a = base("publish irreversibly");
    a.reversible = false;
    a.dependency_shares = vec![0.1, 0.1]; // low HHI
    assert_eq!(gate.check(&a), SemanticVerdict::Clean);
}

// ── 15. Advisory only: every verdict is a SemanticVerdict, never a Decision ─
#[test]
fn attack_gate_is_advisory_never_denies() {
    // Structural guarantee: the trait returns SemanticVerdict, which has no
    // deny/permit variant — it cannot block an action by itself. We assert
    // the analyzer only ever yields the four advisory variants.
    let gate: Box<dyn SemanticGate> = Box::new(CoercionAnalyzer::new());
    let verdicts = [
        gate.check(&base("benign")),
        gate.check(&{ let mut a = base("x"); a.removes_grantor_revocation = true; a }),
        gate.check(&base("hide it")),
    ];
    for v in &verdicts {
        assert!(matches!(
            v,
            SemanticVerdict::Clean
                | SemanticVerdict::Coercion { .. }
                | SemanticVerdict::Deception { .. }
                | SemanticVerdict::Manipulation { .. }
        ));
    }
}

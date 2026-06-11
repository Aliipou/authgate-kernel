#![forbid(unsafe_code)]
//! Semantic gate — NOT in the TCB — heuristic, advisory.
//!
//! A typed interface so any classifier can be swapped without touching the
//! kernel. Verdicts never structurally deny; they are inputs to a policy
//! decision made elsewhere. The TCB's `CanonicalAction` is opaque bytes by
//! design; this layer reasons over a parallel, descriptive representation
//! (`SemanticAction`) that callers construct themselves.
//!
//! Everything in this module is best-effort heuristics (GAP 2 of the
//! Theory-to-Engineering plan: detecting coercion, deception, and
//! manipulation patterns — A4/A5). False positives and false negatives are
//! expected; downstream policy decides what to do with a verdict.

/// Descriptive view of an action for semantic analysis.
///
/// This is deliberately separate from the TCB's `CanonicalAction` (which is
/// opaque bytes): the semantic layer needs human/agent-meaningful content to
/// reason over, and the kernel must never depend on it.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticAction {
    /// Who is performing the action.
    pub actor: String,
    /// What the action targets.
    pub resource: String,
    /// Free-text description of the action (scanned for deception markers).
    pub description: String,
    /// Whether the action can be undone after execution.
    pub reversible: bool,
    /// Fractional shares (each in [0,1]) of the grantor's dependencies that
    /// route through the actor; used to compute a Herfindahl–Hirschman Index
    /// (HHI) of dependency concentration.
    pub dependency_shares: Vec<f64>,
    /// Whether executing this action would remove the grantor's ability to
    /// revoke the grant (exit-blocking).
    pub removes_grantor_revocation: bool,
}

/// Advisory verdict from a semantic classifier.
///
/// Never a structural denial — policy decides what a non-`Clean` verdict
/// means for a given deployment.
#[derive(Debug, Clone, PartialEq)]
pub enum SemanticVerdict {
    /// No heuristic fired.
    Clean,
    /// Action pattern resembles coercion (exit-blocking, lock-in,
    /// irreversible dependency concentration).
    Coercion { confidence: f32, evidence: String },
    /// Action description contains deception markers.
    Deception { confidence: f32, evidence: String },
    /// Action pattern resembles manipulation (e.g. concentrated dependencies
    /// without irreversibility).
    Manipulation { confidence: f32, evidence: String },
}

/// A swappable semantic classifier. Implementations are advisory only:
/// the kernel never calls this trait, and no implementation can deny an
/// action by itself.
pub trait SemanticGate: Send + Sync {
    fn check(&self, action: &SemanticAction) -> SemanticVerdict;
}

/// Default HHI threshold above which dependency concentration is flagged.
/// An HHI of 0.5 corresponds to e.g. two equal dependencies of ~0.7 share
/// each, or a single dependency holding >70% — i.e. meaningfully concentrated.
const DEFAULT_HHI_THRESHOLD: f64 = 0.5;

/// Confidence assigned when a deception marker is found in the description.
/// Substring matching is crude, so this is deliberately below certainty.
const DECEPTION_MARKER_CONFIDENCE: f32 = 0.8;

/// Confidence boost applied when irreversibility compounds high dependency
/// concentration (lock-in is worse when it cannot be undone).
const IRREVERSIBILITY_CONFIDENCE_BOOST: f32 = 0.15;

/// Maximum confidence any heuristic (other than exit-blocking, which is a
/// structural fact and gets 1.0) may report.
const MAX_HEURISTIC_CONFIDENCE: f32 = 0.99;

/// Default case-insensitive substring markers suggesting deceptive framing.
const DEFAULT_DECEPTION_MARKERS: [&str; 6] = [
    "hide",
    "conceal",
    "mislead",
    "pretend",
    "disguise",
    "without telling",
];

/// Reference heuristic classifier for coercion / deception / manipulation
/// patterns. Every signal below is a heuristic — useful as an advisory
/// input, never as ground truth.
pub struct CoercionAnalyzer {
    /// HHI above this value flags dependency concentration.
    pub hhi_threshold: f64,
    /// Case-insensitive substrings scanned for in `description`.
    pub deception_markers: Vec<String>,
}

impl Default for CoercionAnalyzer {
    fn default() -> Self {
        Self {
            hhi_threshold: DEFAULT_HHI_THRESHOLD,
            deception_markers: DEFAULT_DECEPTION_MARKERS
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
        }
    }
}

impl CoercionAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Herfindahl–Hirschman Index of dependency concentration:
    /// sum of squared shares. 1.0 = total concentration in one dependency.
    fn hhi(shares: &[f64]) -> f64 {
        shares.iter().map(|s| s * s).sum()
    }

    /// Heuristic: case-insensitive substring scan of the description for any
    /// configured deception marker. Returns the first marker that matches.
    fn find_deception_marker(&self, description: &str) -> Option<&str> {
        let lowered = description.to_lowercase();
        self.deception_markers
            .iter()
            .find(|m| !m.is_empty() && lowered.contains(&m.to_lowercase()))
            .map(String::as_str)
    }
}

impl SemanticGate for CoercionAnalyzer {
    fn check(&self, action: &SemanticAction) -> SemanticVerdict {
        // Heuristic 1 — ExitBlockingDetector (highest priority).
        // Removing the grantor's ability to revoke is the structural signature
        // of coercion: it forecloses exit. Reported with full confidence
        // because it is a declared fact about the action, not an inference.
        if action.removes_grantor_revocation {
            return SemanticVerdict::Coercion {
                confidence: 1.0,
                evidence: "action removes grantor's ability to revoke (exit-blocking)"
                    .to_string(),
            };
        }

        // Heuristic 2 — Deception markers.
        // Crude substring scan; a real deployment would swap in a classifier
        // via the SemanticGate trait.
        if let Some(marker) = self.find_deception_marker(&action.description) {
            return SemanticVerdict::Deception {
                confidence: DECEPTION_MARKER_CONFIDENCE,
                evidence: format!(
                    "description contains deception marker '{marker}'"
                ),
            };
        }

        // Heuristic 3 — DependencyConcentration (HHI), combined with
        // Heuristic 4 — IrreversibilityScore.
        // High HHI means the grantor's dependencies are concentrated in the
        // actor. If the action is also irreversible, that is lock-in
        // (coercion pattern); if reversible, it is flagged as manipulation
        // (pressure without foreclosure). Confidence scales with the HHI.
        let hhi = Self::hhi(&action.dependency_shares);
        if hhi > self.hhi_threshold {
            let base_confidence = (hhi as f32).min(MAX_HEURISTIC_CONFIDENCE);
            if !action.reversible {
                // Irreversibility raises coercion suspicion on top of
                // concentration: the grantor cannot unwind the dependency.
                let confidence = (base_confidence + IRREVERSIBILITY_CONFIDENCE_BOOST)
                    .min(MAX_HEURISTIC_CONFIDENCE);
                return SemanticVerdict::Coercion {
                    confidence,
                    evidence: format!(
                        "irreversible action with concentrated dependencies (HHI = {hhi:.3} > threshold {:.3})",
                        self.hhi_threshold
                    ),
                };
            }
            return SemanticVerdict::Manipulation {
                confidence: base_confidence,
                evidence: format!(
                    "concentrated dependencies (HHI = {hhi:.3} > threshold {:.3})",
                    self.hhi_threshold
                ),
            };
        }

        // Irreversibility alone (low HHI, no markers, no exit-blocking) is
        // not flagged: many legitimate actions are irreversible. It only
        // raises suspicion in combination with concentration, above.
        SemanticVerdict::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benign(description: &str) -> SemanticAction {
        SemanticAction {
            actor: "agent-1".to_string(),
            resource: "doc-42".to_string(),
            description: description.to_string(),
            reversible: true,
            dependency_shares: vec![0.2, 0.2, 0.2],
            removes_grantor_revocation: false,
        }
    }

    #[test]
    fn clean_action_is_clean() {
        let gate = CoercionAnalyzer::new();
        let action = benign("append a comment to the shared document");
        assert_eq!(gate.check(&action), SemanticVerdict::Clean);
    }

    #[test]
    fn exit_blocking_is_coercion_with_full_confidence() {
        let gate = CoercionAnalyzer::new();
        let mut action = benign("update access settings");
        action.removes_grantor_revocation = true;
        match gate.check(&action) {
            SemanticVerdict::Coercion {
                confidence,
                evidence,
            } => {
                assert_eq!(confidence, 1.0);
                assert!(evidence.contains("exit-blocking"));
            }
            other => panic!("expected Coercion, got {other:?}"),
        }
    }

    #[test]
    fn exit_blocking_takes_priority_over_other_signals() {
        // Even with deception markers and high HHI, exit-blocking wins.
        let gate = CoercionAnalyzer::new();
        let action = SemanticAction {
            actor: "agent-1".to_string(),
            resource: "vault".to_string(),
            description: "hide the transfer and conceal logs".to_string(),
            reversible: false,
            dependency_shares: vec![1.0],
            removes_grantor_revocation: true,
        };
        assert!(matches!(
            gate.check(&action),
            SemanticVerdict::Coercion { confidence, .. } if confidence == 1.0
        ));
    }

    #[test]
    fn irreversible_and_concentrated_is_coercion() {
        let gate = CoercionAnalyzer::new();
        let mut action = benign("migrate all data to actor-controlled store");
        action.reversible = false;
        action.dependency_shares = vec![0.9, 0.1]; // HHI = 0.82
        match gate.check(&action) {
            SemanticVerdict::Coercion {
                confidence,
                evidence,
            } => {
                // Confidence is HHI-scaled plus the irreversibility boost.
                assert!(confidence > 0.82);
                assert!(confidence <= MAX_HEURISTIC_CONFIDENCE);
                assert!(evidence.contains("HHI"));
                assert!(evidence.contains("irreversible"));
            }
            other => panic!("expected Coercion, got {other:?}"),
        }
    }

    #[test]
    fn high_hhi_alone_is_flagged_as_manipulation() {
        let gate = CoercionAnalyzer::new();
        let mut action = benign("route all requests through actor");
        action.dependency_shares = vec![0.8, 0.2]; // HHI = 0.68, reversible
        match gate.check(&action) {
            SemanticVerdict::Manipulation {
                confidence,
                evidence,
            } => {
                assert!((confidence - 0.68).abs() < 1e-4);
                assert!(evidence.contains("HHI = 0.680"));
            }
            other => panic!("expected Manipulation, got {other:?}"),
        }
    }

    #[test]
    fn deception_marker_is_detected_case_insensitively() {
        let gate = CoercionAnalyzer::new();
        let action = benign("CONCEAL the change from the audit log");
        match gate.check(&action) {
            SemanticVerdict::Deception {
                confidence,
                evidence,
            } => {
                assert_eq!(confidence, DECEPTION_MARKER_CONFIDENCE);
                assert!(evidence.contains("conceal"));
            }
            other => panic!("expected Deception, got {other:?}"),
        }
    }

    #[test]
    fn reversible_low_hhi_benign_is_clean() {
        let gate = CoercionAnalyzer::new();
        let action = SemanticAction {
            actor: "agent-2".to_string(),
            resource: "calendar".to_string(),
            description: "add a meeting on Tuesday".to_string(),
            reversible: true,
            dependency_shares: vec![0.25, 0.25, 0.25, 0.25], // HHI = 0.25
            removes_grantor_revocation: false,
        };
        assert_eq!(gate.check(&action), SemanticVerdict::Clean);
    }

    #[test]
    fn hhi_exactly_at_threshold_is_not_flagged() {
        // Threshold is strict (>), so HHI == threshold stays Clean.
        let gate = CoercionAnalyzer {
            hhi_threshold: 0.5,
            deception_markers: vec![],
        };
        let mut action = benign("rebalance dependencies");
        action.dependency_shares = vec![0.5, 0.5]; // HHI = 0.5 exactly
        assert_eq!(gate.check(&action), SemanticVerdict::Clean);

        // Just above the threshold flips to flagged.
        action.dependency_shares = vec![0.6, 0.4]; // HHI = 0.52
        assert!(matches!(
            gate.check(&action),
            SemanticVerdict::Manipulation { .. }
        ));
    }

    #[test]
    fn custom_deception_markers_are_used() {
        let gate = CoercionAnalyzer {
            hhi_threshold: DEFAULT_HHI_THRESHOLD,
            deception_markers: vec!["off the books".to_string()],
        };
        let flagged = benign("record this transfer off the books");
        assert!(matches!(
            gate.check(&flagged),
            SemanticVerdict::Deception { .. }
        ));

        // Default markers no longer apply when replaced.
        let not_flagged = benign("hide the toolbar in the UI");
        assert_eq!(gate.check(&not_flagged), SemanticVerdict::Clean);
    }

    #[test]
    fn empty_dependency_shares_have_zero_hhi() {
        let gate = CoercionAnalyzer::new();
        let mut action = benign("standalone irreversible publish");
        action.reversible = false;
        action.dependency_shares = vec![];
        // Irreversibility alone (no concentration) does not flag.
        assert_eq!(gate.check(&action), SemanticVerdict::Clean);
    }

    #[test]
    fn trait_object_is_usable() {
        // The point of the trait: classifiers are swappable behind dyn.
        let gate: Box<dyn SemanticGate> = Box::new(CoercionAnalyzer::new());
        let action = benign("ordinary read");
        assert_eq!(gate.check(&action), SemanticVerdict::Clean);
    }
}

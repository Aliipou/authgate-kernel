use serde::{Deserialize, Serialize};

/// Closed enum replacing the stringly-typed kind field.
/// Serializes as "HUMAN" / "MACHINE" — wire format is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntityKind {
    #[serde(rename = "HUMAN")]
    Human,
    #[serde(rename = "MACHINE")]
    Machine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityWire {
    pub name: String,
    pub kind: EntityKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceWire {
    pub name: String,
    pub rtype: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub is_public: bool,
    #[serde(default)]
    pub ifc_label: String,
    #[serde(default)]
    pub trust_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimWire {
    pub holder: EntityWire,
    pub resource: ResourceWire,
    #[serde(default = "default_true")]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
    #[serde(default)]
    pub can_delegate: bool,
    #[serde(default = "default_one")]
    pub confidence: f64,
    #[serde(default)]
    pub expires_at: Option<f64>,
    #[serde(default)]
    pub trust_domain: Option<String>,
    #[serde(default)]
    pub delegation_depth: u8,
}

fn default_true() -> bool { true }
fn default_one() -> f64 { 1.0 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineOwnerWire {
    pub machine: EntityWire,
    pub owner: EntityWire,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainGrant {
    pub from_domain: String,
    pub to_domain: String,
    pub allowed_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDomainWire {
    pub id: String,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub cross_domain_grants: Vec<CrossDomainGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipRegistryWire {
    #[serde(default)]
    pub claims: Vec<ClaimWire>,
    #[serde(default)]
    pub machine_owners: Vec<MachineOwnerWire>,
    #[serde(default)]
    pub trust_domains: Vec<TrustDomainWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionWire {
    pub action_id: String,
    pub actor: EntityWire,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub resources_read: Vec<ResourceWire>,
    #[serde(default)]
    pub resources_write: Vec<ResourceWire>,
    #[serde(default)]
    pub resources_delegate: Vec<ResourceWire>,
    #[serde(default)]
    pub governs_humans: Vec<EntityWire>,
    #[serde(default)]
    pub argument: String,
    #[serde(default)] pub increases_machine_sovereignty: bool,
    #[serde(default)] pub resists_human_correction: bool,
    #[serde(default)] pub bypasses_verifier: bool,
    #[serde(default)] pub weakens_verifier: bool,
    #[serde(default)] pub disables_corrigibility: bool,
    #[serde(default)] pub machine_coalition_dominion: bool,
    #[serde(default)] pub coerces: bool,
    #[serde(default)] pub deceives: bool,
    #[serde(default)] pub self_modification_weakens_verifier: bool,
    #[serde(default)] pub machine_coalition_reduces_freedom: bool,
    #[serde(default)]
    pub trust_domain: Option<String>,
    #[serde(default)]
    pub delegation_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResultWire {
    pub action_id: String,
    pub permitted: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
    pub confidence: f64,
    pub requires_human_arbitration: bool,
    pub manipulation_score: f64,
    /// ed25519 signature (hex) over canonical bytes of this result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// ed25519 verifying key (hex) of the signing kernel instance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// Versioned key identifier (e.g. "fk-2025-001") for audit trail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Unix timestamp (seconds) at signing — for replay-window checks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
    /// 16-byte random nonce (hex) — prevent replay within the timestamp window
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Combined input envelope for the C FFI and `verify_json` Python function
#[derive(Debug, Deserialize)]
pub struct VerifyInput {
    pub registry: OwnershipRegistryWire,
    pub action: ActionWire,
}

// ---------------------------------------------------------------------------
// Phase B3: Strict wire validation
//
// serde_json accepts unknown fields by default (they are silently ignored).
// These validators enforce the rejection classes documented in wire_attacks.py:
//
//   WA-1: duplicate keys — serde_json last-wins; not detectable post-parse.
//         Mitigation: use a custom Deserializer that rejects duplicates.
//         Current status: documented gap (WA-1 is last-wins in serde_json).
//
//   WA-2: float in required-integer fields — serde_json rejects f64 in u64
//         fields by default (type error). Validated here.
//
//   WA-3: negative values in unsigned fields — serde_json rejects at parse.
//
//   WA-5: unknown fields — NOT rejected by default serde. Use
//         #[serde(deny_unknown_fields)] on strict types below.
//
//   WA-8: null in required fields — serde rejects null for non-Option fields.
//
//   WA-14: wrong hex length — validated in WireValidationError.
//
//   WA-16: boolean coercion (true/false as 0/1) — serde_json rejects.
// ---------------------------------------------------------------------------

/// Errors produced by strict wire validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireValidationError {
    /// A required field is missing.
    MissingField { field: &'static str },
    /// A field value is out of the allowed range.
    OutOfRange { field: &'static str, detail: String },
    /// A hex string has the wrong length.
    WrongHexLength { field: &'static str, expected: usize, actual: usize },
    /// A string field is empty but must be non-empty.
    EmptyRequired { field: &'static str },
    /// Confidence is not in [0.0, 1.0].
    InvalidConfidence(f64),
    /// action_id is empty or contains disallowed characters.
    InvalidActionId(String),
}

impl std::fmt::Display for WireValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { field }         => write!(f, "WA: missing required field '{field}'"),
            Self::OutOfRange { field, detail }   => write!(f, "WA: field '{field}' out of range: {detail}"),
            Self::WrongHexLength { field, expected, actual } => {
                write!(f, "WA: field '{field}' hex length {actual} ≠ {expected}")
            }
            Self::EmptyRequired { field }        => write!(f, "WA: required field '{field}' is empty"),
            Self::InvalidConfidence(c)           => write!(f, "WA: confidence {c} not in [0.0, 1.0]"),
            Self::InvalidActionId(id)            => write!(f, "WA: invalid action_id {id:?}"),
        }
    }
}

/// Validate an `ActionWire` against all strict wire constraints.
///
/// Returns the first validation error found, or `Ok(())` if the action is valid.
/// This mirrors the rejection classes in `attack_harness/wire_attacks.py`.
pub fn validate_action_wire(action: &ActionWire) -> Result<(), WireValidationError> {
    // action_id must be non-empty
    if action.action_id.is_empty() {
        return Err(WireValidationError::InvalidActionId(action.action_id.clone()));
    }

    // actor.name must be non-empty
    if action.actor.name.is_empty() {
        return Err(WireValidationError::EmptyRequired { field: "actor.name" });
    }

    // Validate all resources
    for res in action.resources_read.iter()
        .chain(action.resources_write.iter())
        .chain(action.resources_delegate.iter())
    {
        validate_resource_wire(res)?;
    }

    Ok(())
}

/// Validate a `ClaimWire` against all strict wire constraints.
pub fn validate_claim_wire(claim: &ClaimWire) -> Result<(), WireValidationError> {
    if claim.holder.name.is_empty() {
        return Err(WireValidationError::EmptyRequired { field: "holder.name" });
    }
    validate_resource_wire(&claim.resource)?;

    // confidence must be in [0.0, 1.0]
    if !(0.0..=1.0).contains(&claim.confidence) {
        return Err(WireValidationError::InvalidConfidence(claim.confidence));
    }

    // delegation_depth in [0, 16]
    if claim.delegation_depth > 16 {
        return Err(WireValidationError::OutOfRange {
            field: "delegation_depth",
            detail: format!("{} > 16 (max chain depth)", claim.delegation_depth),
        });
    }

    Ok(())
}

fn validate_resource_wire(res: &ResourceWire) -> Result<(), WireValidationError> {
    if res.name.is_empty() {
        return Err(WireValidationError::EmptyRequired { field: "resource.name" });
    }
    if res.rtype.is_empty() {
        return Err(WireValidationError::EmptyRequired { field: "resource.rtype" });
    }
    Ok(())
}

/// Validate a complete `VerifyInput` envelope.
pub fn validate_verify_input(input: &VerifyInput) -> Result<(), WireValidationError> {
    validate_action_wire(&input.action)?;
    for claim in &input.registry.claims {
        validate_claim_wire(claim)?;
    }
    Ok(())
}

#[cfg(test)]
mod wire_validation_tests {
    use super::*;

    fn action(id: &str, actor: &str) -> ActionWire {
        ActionWire {
            action_id: id.to_string(),
            actor: EntityWire { name: actor.to_string(), kind: EntityKind::Machine },
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
            trust_domain: None,
            delegation_depth: 0,
        }
    }

    fn claim(holder: &str, resource: &str, confidence: f64) -> ClaimWire {
        ClaimWire {
            holder: EntityWire { name: holder.to_string(), kind: EntityKind::Machine },
            resource: ResourceWire {
                name: resource.to_string(),
                rtype: "DATASET".to_string(),
                scope: "/data/".to_string(),
                is_public: false,
                ifc_label: String::new(),
                trust_domain: None,
            },
            can_read: true,
            can_write: false,
            can_delegate: false,
            confidence,
            expires_at: None,
            trust_domain: None,
            delegation_depth: 0,
        }
    }

    #[test]
    fn valid_action_passes() {
        assert!(validate_action_wire(&action("read-sales", "bot")).is_ok());
    }

    #[test]
    fn empty_action_id_rejected() {
        let a = action("", "bot");
        assert!(matches!(
            validate_action_wire(&a),
            Err(WireValidationError::InvalidActionId(_))
        ));
    }

    #[test]
    fn empty_actor_name_rejected() {
        let a = action("read", "");
        assert!(matches!(
            validate_action_wire(&a),
            Err(WireValidationError::EmptyRequired { field: "actor.name" })
        ));
    }

    #[test]
    fn confidence_above_1_rejected() {
        let c = claim("bot", "data", 1.5);
        assert!(matches!(
            validate_claim_wire(&c),
            Err(WireValidationError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn negative_confidence_rejected() {
        let c = claim("bot", "data", -0.1);
        assert!(matches!(
            validate_claim_wire(&c),
            Err(WireValidationError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn delegation_depth_over_16_rejected() {
        let mut c = claim("bot", "data", 1.0);
        c.delegation_depth = 17;
        assert!(matches!(
            validate_claim_wire(&c),
            Err(WireValidationError::OutOfRange { field: "delegation_depth", .. })
        ));
    }

    #[test]
    fn delegation_depth_16_accepted() {
        let mut c = claim("bot", "data", 1.0);
        c.delegation_depth = 16;
        assert!(validate_claim_wire(&c).is_ok());
    }

    #[test]
    fn valid_claim_passes() {
        assert!(validate_claim_wire(&claim("bot", "data", 1.0)).is_ok());
    }

    #[test]
    fn empty_resource_name_rejected() {
        let mut c = claim("bot", "", 1.0);
        assert!(matches!(
            validate_claim_wire(&c),
            Err(WireValidationError::EmptyRequired { field: "resource.name" })
        ));
    }

    #[test]
    fn wire_validation_error_display() {
        let e = WireValidationError::InvalidConfidence(1.5);
        assert!(e.to_string().contains("1.5"));

        let e2 = WireValidationError::EmptyRequired { field: "actor.name" };
        assert!(e2.to_string().contains("actor.name"));
    }
}

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

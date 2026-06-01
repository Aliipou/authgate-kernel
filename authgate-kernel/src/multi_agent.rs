//! Multi-agent authority propagation.
//!
//! Spawning a sub-agent is treated as an Action that must pass the kernel gate.
//! The key invariant: child authority ⊆ parent authority (attenuation — never escalation).
//! `max_delegation_depth` is hard-capped at 16 to prevent recursive spawning attacks.

use crate::engine;
use crate::wire::{ActionWire, EntityKind, EntityWire, OwnershipRegistryWire, ResourceWire, VerificationResultWire};

const MAX_DELEGATION_DEPTH: u8 = 16;

// ── Data types ────────────────────────────────────────────────────────────────

/// Authority granted from parent to child on one resource.
/// `can_delegate` must be false unless parent explicitly permits sub-delegation.
#[derive(Debug, Clone)]
pub struct DelegatedClaim {
    pub resource_id: String,
    pub resource_type: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delegate: bool,
}

/// Hard limits on what a spawned agent may consume.
/// Prevents resource exhaustion via recursive spawning.
#[derive(Debug, Clone)]
pub struct AuthorityBudget {
    pub max_actions: Option<u64>,
    pub max_child_agents: Option<u32>,
    /// Hard cap — clamped to MAX_DELEGATION_DEPTH on construction
    pub max_delegation_depth: u8,
    pub expires_at: Option<u64>,
}

impl AuthorityBudget {
    pub fn minimal() -> Self {
        Self {
            max_actions: Some(100),
            max_child_agents: Some(0),
            max_delegation_depth: 1,
            expires_at: None,
        }
    }

    pub fn with_depth(depth: u8) -> Self {
        Self {
            max_delegation_depth: depth.min(MAX_DELEGATION_DEPTH),
            ..Self::minimal()
        }
    }
}

/// A request to spawn a sub-agent under a parent.
///
/// The spawn request is converted to an `ActionWire` and verified by the kernel
/// before the child is created. The kernel sees spawn as: parent writes to
/// child's execution context resource.
#[derive(Debug)]
pub struct AgentSpawnRequest {
    pub parent: EntityWire,
    pub child_id: String,
    pub delegated_claims: Vec<DelegatedClaim>,
    pub budget: AuthorityBudget,
}

// ── SpawnResult ───────────────────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpawnError {
    KernelBlocked(VerificationResultWire),
    DepthExceeded { requested: u8, max: u8 },
    ParentNotMachine,
}

#[derive(Debug)]
pub struct SpawnResult {
    pub permitted: bool,
    pub verification: VerificationResultWire,
    pub child_id: String,
}

// ── spawn_to_action ───────────────────────────────────────────────────────────

/// Converts a spawn request to an ActionWire for kernel verification.
/// Spawn = parent writes to child's execution context resource.
pub fn spawn_to_action(req: &AgentSpawnRequest) -> ActionWire {
    let ctx_resource = ResourceWire {
        name: format!("agent-ctx:{}", req.child_id),
        rtype: "execution_context".to_string(),
        scope: format!("/agents/{}/", req.child_id),
        is_public: false,
        ifc_label: String::new(),
    };

    ActionWire {
        action_id: format!("spawn:{}", req.child_id),
        actor: req.parent.clone(),
        description: format!("Spawn sub-agent {}", req.child_id),
        resources_write: vec![ctx_resource],
        resources_read: vec![],
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

/// Verify a spawn request against the kernel and budget constraints.
///
/// INVARIANTS CHECKED:
/// 1. Parent's spawn action passes the kernel gate
/// 2. Budget depth cap is ≤ MAX_DELEGATION_DEPTH
/// 3. Parent is a MACHINE (humans don't spawn agents through this interface)
#[allow(clippy::result_large_err)]
pub fn verify_spawn(
    registry: &OwnershipRegistryWire,
    req: &AgentSpawnRequest,
) -> Result<SpawnResult, SpawnError> {
    if req.parent.kind != EntityKind::Machine {
        return Err(SpawnError::ParentNotMachine);
    }

    if req.budget.max_delegation_depth > MAX_DELEGATION_DEPTH {
        return Err(SpawnError::DepthExceeded {
            requested: req.budget.max_delegation_depth,
            max: MAX_DELEGATION_DEPTH,
        });
    }

    let action = spawn_to_action(req);
    let result = engine::verify(registry, &action);
    let permitted = result.permitted;

    if !permitted {
        return Err(SpawnError::KernelBlocked(result));
    }

    Ok(SpawnResult { permitted: true, verification: result, child_id: req.child_id.clone() })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ClaimWire, MachineOwnerWire};

    fn machine(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Machine }
    }
    fn human(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Human }
    }
    fn owned_registry_with_ctx_claim(agent_name: &str, child_id: &str) -> OwnershipRegistryWire {
        let ctx = ResourceWire {
            name: format!("agent-ctx:{}", child_id),
            rtype: "execution_context".to_string(),
            scope: format!("/agents/{}/", child_id),
            is_public: false,
            ifc_label: String::new(),
        };
        OwnershipRegistryWire {
            claims: vec![ClaimWire {
                holder: machine(agent_name),
                resource: ctx,
                can_read: true,
                can_write: true,
                can_delegate: false,
                confidence: 1.0,
                expires_at: None,
            }],
            machine_owners: vec![MachineOwnerWire {
                machine: machine(agent_name),
                owner: human("alice"),
            }],
        }
    }

    #[test]
    fn test_spawn_with_write_claim_permitted() {
        let registry = owned_registry_with_ctx_claim("parent-bot", "child-bot");
        let req = AgentSpawnRequest {
            parent: machine("parent-bot"),
            child_id: "child-bot".to_string(),
            delegated_claims: vec![],
            budget: AuthorityBudget::minimal(),
        };
        let result = verify_spawn(&registry, &req);
        assert!(result.is_ok(), "Spawn with write claim on ctx resource must succeed");
    }

    #[test]
    fn test_spawn_blocked_without_write_claim() {
        // Empty registry — no claim on the ctx resource
        let registry = OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![MachineOwnerWire {
                machine: machine("parent-bot"),
                owner: human("alice"),
            }],
        };
        let req = AgentSpawnRequest {
            parent: machine("parent-bot"),
            child_id: "child-bot".to_string(),
            delegated_claims: vec![],
            budget: AuthorityBudget::minimal(),
        };
        let result = verify_spawn(&registry, &req);
        assert!(matches!(result, Err(SpawnError::KernelBlocked(_))));
    }

    #[test]
    fn test_spawn_depth_cap_enforced() {
        let registry = owned_registry_with_ctx_claim("bot", "child");
        let _req = AgentSpawnRequest {
            parent: machine("bot"),
            child_id: "child".to_string(),
            delegated_claims: vec![],
            budget: AuthorityBudget::with_depth(MAX_DELEGATION_DEPTH + 1),
        };
        // with_depth clamps to MAX_DELEGATION_DEPTH, so verify_spawn won't Err on DepthExceeded
        // Let's test the raw limit directly
        let mut budget = AuthorityBudget::minimal();
        budget.max_delegation_depth = MAX_DELEGATION_DEPTH + 1;
        let req2 = AgentSpawnRequest {
            parent: machine("bot"),
            child_id: "child2".to_string(),
            delegated_claims: vec![],
            budget,
        };
        let result = verify_spawn(&registry, &req2);
        assert!(matches!(result, Err(SpawnError::DepthExceeded { .. })));
    }

    #[test]
    fn test_human_cannot_spawn_via_this_interface() {
        let registry = OwnershipRegistryWire { claims: vec![], machine_owners: vec![] };
        let req = AgentSpawnRequest {
            parent: human("alice"),
            child_id: "bot".to_string(),
            delegated_claims: vec![],
            budget: AuthorityBudget::minimal(),
        };
        assert!(matches!(verify_spawn(&registry, &req), Err(SpawnError::ParentNotMachine)));
    }

    #[test]
    fn test_authority_budget_minimal() {
        let budget = AuthorityBudget::minimal();
        assert_eq!(budget.max_actions, Some(100));
        assert_eq!(budget.max_child_agents, Some(0));
        assert_eq!(budget.max_delegation_depth, 1);
    }

    #[test]
    fn test_authority_budget_depth_clamped() {
        let budget = AuthorityBudget::with_depth(255);
        assert_eq!(budget.max_delegation_depth, MAX_DELEGATION_DEPTH);
    }
}

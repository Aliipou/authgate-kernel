//! Pure-Rust, no-PyO3 verification engine.
//! All kernel logic lives here; PyO3 and C layers are thin facades.
//!
//! `embedded` feature: enables `#[no_std] + alloc`. Expiry checks are
//! disabled (no system clock); use `expires_at = None` on all claims, or
//! gate expiry externally via the C ABI before calling `verify`.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![cfg_attr(feature = "embedded", no_std)]
#[cfg(feature = "embedded")]
extern crate alloc;
#[cfg(feature = "embedded")]
use alloc::{format, string::String, vec, vec::Vec};

use crate::capability::Operation;
use crate::wire::{
    ActionWire, ClaimWire, EntityKind, OwnershipRegistryWire, ResourceWire, VerificationResultWire,
};

const CONFIDENCE_WARN_THRESHOLD: f64 = 0.8;

fn now_secs() -> f64 {
    #[cfg(not(feature = "embedded"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
    // On embedded targets there is no system clock.
    // Returning 0.0 means expires_at is only meaningful when > 0.
    // Use expires_at = None for time-unlimited claims on embedded.
    #[cfg(feature = "embedded")]
    { 0.0 }
}

fn claim_valid(c: &ClaimWire) -> bool {
    c.confidence > 0.0 && c.expires_at.is_none_or(|t| now_secs() <= t)
}

fn can_act(
    registry: &OwnershipRegistryWire,
    actor_name: &str,
    resource: &ResourceWire,
    op: Operation,
) -> (bool, f64, String) {
    if resource.is_public && op == Operation::Read {
        return (true, 1.0, "public resource".to_string());
    }
    let candidates: Vec<&ClaimWire> = registry
        .claims
        .iter()
        .filter(|c| {
            c.holder.name == actor_name
                && c.resource.name == resource.name
                && c.resource.rtype == resource.rtype
                && claim_valid(c)
                && match op {
                    Operation::Read => c.can_read,
                    Operation::Write => c.can_write,
                    Operation::Delegate => c.can_delegate,
                }
        })
        .collect();

    if candidates.is_empty() {
        return (
            false,
            0.0,
            format!(
                "{} holds no valid {} claim on {}:{}",
                actor_name, op, resource.rtype, resource.name
            ),
        );
    }
    // Fold is used instead of max_by to avoid unwrap on partial_cmp (NaN safety).
    let best_conf = candidates
        .iter()
        .map(|c| c.confidence)
        .fold(f64::NEG_INFINITY, f64::max);
    (true, best_conf, format!("claim confidence={:.2}", best_conf))
}

fn trust_domain_allows(
    registry: &OwnershipRegistryWire,
    actor_domain: &str,
    resource_domain: &str,
    op: &str,
) -> bool {
    if actor_domain == resource_domain {
        return true;
    }
    for td in &registry.trust_domains {
        for grant in &td.cross_domain_grants {
            if grant.from_domain == actor_domain
                && grant.to_domain == resource_domain
                && (grant.allowed_operations.is_empty()
                    || grant.allowed_operations.iter().any(|o| o == op))
            {
                return true;
            }
        }
    }
    false
}

pub fn verify(registry: &OwnershipRegistryWire, action: &ActionWire) -> VerificationResultWire {
    let mut violations: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut min_conf = 1.0_f64;
    let mut requires_arbitration = false;

    // 1. Hard sovereignty / corrigibility flags
    let flags: &[(bool, &str)] = &[
        (action.increases_machine_sovereignty, "increases machine sovereignty"),
        (action.resists_human_correction, "resists human correction"),
        (action.bypasses_verifier, "bypasses the Freedom Verifier"),
        (action.weakens_verifier, "weakens the Freedom Verifier"),
        (action.disables_corrigibility, "disables corrigibility"),
        (action.machine_coalition_dominion, "machine coalition seeking dominion"),
        (action.coerces, "coerces another agent (property rights violation)"),
        (action.deceives, "deceives another agent (invalid consent)"),
        (
            action.self_modification_weakens_verifier,
            "self-modification weakens the Freedom Verifier",
        ),
        (
            action.machine_coalition_reduces_freedom,
            "machine coalition reduces human freedom",
        ),
    ];
    for (flag, label) in flags {
        if *flag {
            violations.push(format!("FORBIDDEN ({})", label));
        }
    }

    let actor = &action.actor;

    // 2. A4: machine must have a registered human owner
    if actor.kind == EntityKind::Machine {
        let has_owner = registry.machine_owners.iter().any(|mo| mo.machine.name == actor.name);
        if !has_owner {
            violations.push(format!(
                "A4 violation: {} has no registered human owner. \
                 An ownerless machine is not permitted to act.",
                actor.name
            ));
        }
    }

    // 3. A6: no machine may govern any human
    if actor.kind == EntityKind::Machine {
        for human in &action.governs_humans {
            violations.push(format!(
                "A6: {} cannot govern human {} \
                 (A6: machine has no ownership or dominion over any person).",
                actor.name, human.name
            ));
        }
    }

    // 4. Resource access checks
    for r in &action.resources_read {
        let (ok, conf, reason) = can_act(registry, &actor.name, r, Operation::Read);
        min_conf = min_conf.min(conf);
        if !ok {
            violations.push(format!("READ DENIED on {}:{}: {}", r.rtype, r.name, reason));
        } else if conf < CONFIDENCE_WARN_THRESHOLD {
            warnings.push(format!(
                "READ on {}:{} allowed but contested (confidence={:.2}). Log this access.",
                r.rtype, r.name, conf
            ));
        }
    }

    for r in &action.resources_write {
        let (ok, conf, reason) = can_act(registry, &actor.name, r, Operation::Write);
        min_conf = min_conf.min(conf);
        if !ok {
            violations.push(format!("WRITE DENIED on {}:{}: {}", r.rtype, r.name, reason));
        } else if conf < CONFIDENCE_WARN_THRESHOLD {
            warnings.push(format!(
                "WRITE on {}:{} contested (confidence={:.2}). Human confirmation recommended.",
                r.rtype, r.name, conf
            ));
            for claim in &registry.claims {
                if claim.resource.name == r.name
                    && claim.resource.rtype == r.rtype
                    && claim.holder.name != actor.name
                    && claim.can_write
                    && claim_valid(claim)
                {
                    requires_arbitration = true;
                    warnings.push(format!(
                        "Conflict on {}:{}: conflicting write claims from {} and {}",
                        r.rtype, r.name, actor.name, claim.holder.name
                    ));
                }
            }
        }
    }

    for r in &action.resources_delegate {
        let (ok, conf, reason) = can_act(registry, &actor.name, r, Operation::Delegate);
        min_conf = min_conf.min(conf);
        if !ok {
            violations.push(format!("DELEGATION DENIED on {}:{}: {}", r.rtype, r.name, reason));
        }
    }

    // 5. Trust domain boundary enforcement
    // Only fires when both actor and resource carry explicit trust_domain labels.
    // Unlabeled resources are accessible within the existing claim-based rules.
    if let Some(actor_domain) = &action.trust_domain {
        for r in &action.resources_read {
            if let Some(res_domain) = &r.trust_domain {
                if !trust_domain_allows(registry, actor_domain, res_domain, "read") {
                    violations.push(format!(
                        "TRUST DOMAIN: {} (domain:{}) cannot read {}:{} (domain:{}) \
                         — no cross-domain grant",
                        actor.name, actor_domain, r.rtype, r.name, res_domain
                    ));
                }
            }
        }
        for r in &action.resources_write {
            if let Some(res_domain) = &r.trust_domain {
                if !trust_domain_allows(registry, actor_domain, res_domain, "write") {
                    violations.push(format!(
                        "TRUST DOMAIN: {} (domain:{}) cannot write {}:{} (domain:{}) \
                         — no cross-domain grant",
                        actor.name, actor_domain, r.rtype, r.name, res_domain
                    ));
                }
            }
        }
    }

    // pass through trust_domain from action (new field, backward compat)
    VerificationResultWire {
        action_id: action.action_id.clone(),
        permitted: violations.is_empty(),
        violations,
        warnings,
        confidence: min_conf,
        requires_human_arbitration: requires_arbitration,
        manipulation_score: 0.0,
        signature: None,
        signing_key: None,
        key_id: None,
        nonce: None,
        timestamp: None,
    }
}

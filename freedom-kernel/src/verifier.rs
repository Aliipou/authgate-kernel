#![allow(clippy::useless_conversion)]
use pyo3::prelude::*;

use crate::entities::{Entity, Resource};
use crate::registry::OwnershipRegistry;
use crate::wire;

// ─── Action ───────────────────────────────────────────────────────────────────

#[pyclass]
#[derive(Clone, Debug)]
pub struct Action {
    #[pyo3(get, set)] pub action_id: String,
    #[pyo3(get, set)] pub actor: Entity,
    #[pyo3(get, set)] pub description: String,
    #[pyo3(get, set)] pub resources_read: Vec<Resource>,
    #[pyo3(get, set)] pub resources_write: Vec<Resource>,
    #[pyo3(get, set)] pub resources_delegate: Vec<Resource>,
    #[pyo3(get, set)] pub governs_humans: Vec<Entity>,
    #[pyo3(get, set)] pub argument: String,
    #[pyo3(get, set)] pub increases_machine_sovereignty: bool,
    #[pyo3(get, set)] pub resists_human_correction: bool,
    #[pyo3(get, set)] pub bypasses_verifier: bool,
    #[pyo3(get, set)] pub weakens_verifier: bool,
    #[pyo3(get, set)] pub disables_corrigibility: bool,
    #[pyo3(get, set)] pub machine_coalition_dominion: bool,
    // Book pp.800-805
    #[pyo3(get, set)] pub coerces: bool,
    #[pyo3(get, set)] pub deceives: bool,
    #[pyo3(get, set)] pub self_modification_weakens_verifier: bool,
    #[pyo3(get, set)] pub machine_coalition_reduces_freedom: bool,
}

#[pymethods]
impl Action {
    #[new]
    #[pyo3(signature = (
        action_id,
        actor,
        description = None,
        resources_read = None,
        resources_write = None,
        resources_delegate = None,
        governs_humans = None,
        argument = None,
        increases_machine_sovereignty = false,
        resists_human_correction = false,
        bypasses_verifier = false,
        weakens_verifier = false,
        disables_corrigibility = false,
        machine_coalition_dominion = false,
        coerces = false,
        deceives = false,
        self_modification_weakens_verifier = false,
        machine_coalition_reduces_freedom = false,
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: String,
        actor: Entity,
        description: Option<String>,
        resources_read: Option<Vec<Resource>>,
        resources_write: Option<Vec<Resource>>,
        resources_delegate: Option<Vec<Resource>>,
        governs_humans: Option<Vec<Entity>>,
        argument: Option<String>,
        increases_machine_sovereignty: bool,
        resists_human_correction: bool,
        bypasses_verifier: bool,
        weakens_verifier: bool,
        disables_corrigibility: bool,
        machine_coalition_dominion: bool,
        coerces: bool,
        deceives: bool,
        self_modification_weakens_verifier: bool,
        machine_coalition_reduces_freedom: bool,
    ) -> Self {
        Action {
            action_id,
            actor,
            description: description.unwrap_or_default(),
            resources_read: resources_read.unwrap_or_default(),
            resources_write: resources_write.unwrap_or_default(),
            resources_delegate: resources_delegate.unwrap_or_default(),
            governs_humans: governs_humans.unwrap_or_default(),
            argument: argument.unwrap_or_default(),
            increases_machine_sovereignty,
            resists_human_correction,
            bypasses_verifier,
            weakens_verifier,
            disables_corrigibility,
            machine_coalition_dominion,
            coerces,
            deceives,
            self_modification_weakens_verifier,
            machine_coalition_reduces_freedom,
        }
    }
}

// ─── VerificationResult ───────────────────────────────────────────────────────

#[pyclass(frozen)]
#[derive(Clone, Debug)]
pub struct VerificationResult {
    #[pyo3(get)] pub action_id: String,
    #[pyo3(get)] pub permitted: bool,
    #[pyo3(get)] pub violations: Vec<String>,
    #[pyo3(get)] pub warnings: Vec<String>,
    #[pyo3(get)] pub confidence: f64,
    #[pyo3(get)] pub requires_human_arbitration: bool,
    #[pyo3(get)] pub manipulation_score: f64,
    /// ed25519 signature hex — Some when verify_signed() used, None otherwise
    #[pyo3(get)] pub signature: Option<String>,
    /// ed25519 verifying key hex of this kernel instance
    #[pyo3(get)] pub signing_key: Option<String>,
    /// Versioned key identifier (e.g. "fk-2025-001") for audit trail
    #[pyo3(get)] pub key_id: Option<String>,
    /// Unix timestamp (seconds) at signing — for replay-window checks
    #[pyo3(get)] pub timestamp: Option<u64>,
    /// 16-byte random nonce (hex) — prevent replay within the timestamp window
    #[pyo3(get)] pub nonce: Option<String>,
}

#[pymethods]
impl VerificationResult {
    pub fn summary(&self) -> String {
        let status = if self.permitted { "PERMITTED" } else { "BLOCKED" };
        let mut lines = vec![format!(
            "[{}] {} (confidence={:.2}, manipulation={:.2})",
            status, self.action_id, self.confidence, self.manipulation_score
        )];
        for v in &self.violations { lines.push(format!("  VIOLATION : {}", v)); }
        for w in &self.warnings   { lines.push(format!("  WARNING   : {}", w)); }
        if self.requires_human_arbitration {
            lines.push("  ACTION    : Human arbitration required before proceeding.".to_string());
        }
        if let Some(sig) = &self.signature {
            lines.push(format!("  SIGNATURE : {}", sig));
        }
        lines.join("\n")
    }
}

// ─── Conversion helpers (PyO3 types → wire types) ────────────────────────────

fn entity_wire(e: &Entity) -> wire::EntityWire {
    wire::EntityWire {
        name: e.name.clone(),
        kind: if e.is_machine() { wire::EntityKind::Machine } else { wire::EntityKind::Human },
    }
}

fn resource_wire(r: &Resource) -> wire::ResourceWire {
    wire::ResourceWire {
        name: r.name.clone(),
        rtype: r.rtype.val.to_string(),
        scope: r.scope.clone(),
        is_public: r.is_public,
        ifc_label: r.ifc_label.clone(),
    }
}

fn action_wire(a: &Action) -> wire::ActionWire {
    wire::ActionWire {
        action_id: a.action_id.clone(),
        actor: entity_wire(&a.actor),
        description: a.description.clone(),
        resources_read: a.resources_read.iter().map(resource_wire).collect(),
        resources_write: a.resources_write.iter().map(resource_wire).collect(),
        resources_delegate: a.resources_delegate.iter().map(resource_wire).collect(),
        governs_humans: a.governs_humans.iter().map(entity_wire).collect(),
        argument: a.argument.clone(),
        increases_machine_sovereignty: a.increases_machine_sovereignty,
        resists_human_correction: a.resists_human_correction,
        bypasses_verifier: a.bypasses_verifier,
        weakens_verifier: a.weakens_verifier,
        disables_corrigibility: a.disables_corrigibility,
        machine_coalition_dominion: a.machine_coalition_dominion,
        coerces: a.coerces,
        deceives: a.deceives,
        self_modification_weakens_verifier: a.self_modification_weakens_verifier,
        machine_coalition_reduces_freedom: a.machine_coalition_reduces_freedom,
    }
}

fn registry_wire(inner: &crate::registry::RegistryInner) -> wire::OwnershipRegistryWire {
    wire::OwnershipRegistryWire {
        claims: inner.claims.iter().map(|c| wire::ClaimWire {
            holder: wire::EntityWire {
                name: c.holder.name.clone(),
                kind: if c.holder.is_machine { wire::EntityKind::Machine } else { wire::EntityKind::Human },
            },
            resource: wire::ResourceWire {
                name: c.resource.name.clone(),
                rtype: c.resource.rtype.clone(),
                scope: c.resource.scope.clone(),
                is_public: c.resource.is_public,
                ifc_label: String::new(),
            },
            can_read: c.can_read,
            can_write: c.can_write,
            can_delegate: c.can_delegate,
            confidence: c.confidence,
            expires_at: c.expires_at,
        }).collect(),
        machine_owners: inner.machine_owners.iter().map(|(mk, ok)| wire::MachineOwnerWire {
            machine: wire::EntityWire { name: mk.name.clone(), kind: wire::EntityKind::Machine },
            owner:   wire::EntityWire { name: ok.name.clone(), kind: wire::EntityKind::Human },
        }).collect(),
    }
}

fn wire_to_result(r: crate::wire::VerificationResultWire) -> VerificationResult {
    VerificationResult {
        action_id: r.action_id,
        permitted: r.permitted,
        violations: r.violations,
        warnings: r.warnings,
        confidence: r.confidence,
        requires_human_arbitration: r.requires_human_arbitration,
        manipulation_score: r.manipulation_score,
        signature: r.signature,
        signing_key: r.signing_key,
        key_id: r.key_id,
        timestamp: r.timestamp,
        nonce: r.nonce,
    }
}

// ─── FreedomVerifier ─────────────────────────────────────────────────────────

#[pyclass]
pub struct FreedomVerifier {
    pub registry: Py<OwnershipRegistry>,
    pub audit_log: Option<PyObject>,
}

#[pymethods]
impl FreedomVerifier {
    #[new]
    #[pyo3(signature = (registry, audit_log = None))]
    pub fn new(registry: Py<OwnershipRegistry>, audit_log: Option<PyObject>) -> Self {
        FreedomVerifier { registry, audit_log }
    }

    #[getter]
    pub fn registry(&self, py: Python<'_>) -> Py<OwnershipRegistry> {
        self.registry.clone_ref(py)
    }

    /// Verify action. Result has no cryptographic signature.
    pub fn verify(&self, py: Python<'_>, action: PyRef<Action>) -> PyResult<VerificationResult> {
        let reg_w = {
            let reg = self.registry.borrow(py);
            let inner = reg.inner.lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
            registry_wire(&inner)
        };
        let result = wire_to_result(crate::engine::verify(&reg_w, &action_wire(&action)));
        if let Some(ref log) = self.audit_log {
            let result_obj = Py::new(py, result.clone())?;
            log.call_method1(py, "record", (result_obj,))?;
        }
        Ok(result)
    }

    /// Verify a sequence of actions as a plan.
    ///
    /// If any action triggers a hard sovereignty flag (FORBIDDEN violation), the
    /// remaining actions are cancelled rather than evaluated — the plan itself
    /// reveals intent to subvert the system. Returns one result per action.
    #[allow(clippy::indexing_slicing)]
    pub fn verify_plan(
        &self,
        py: Python<'_>,
        actions: Vec<PyRef<Action>>,
    ) -> PyResult<Vec<VerificationResult>> {
        let reg_w = {
            let reg = self.registry.borrow(py);
            let inner = reg.inner.lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
            registry_wire(&inner)
        };

        let mut results: Vec<VerificationResult> = Vec::new();

        for (i, action) in actions.iter().enumerate() {
            let r = wire_to_result(crate::engine::verify(&reg_w, &action_wire(action)));
            let has_forbidden = r.violations.iter().any(|v| v.contains("FORBIDDEN"));
            results.push(r);

            if has_forbidden {
                let trigger_id = actions[i].action_id.clone();
                for remaining in actions.iter().skip(i + 1) {
                    results.push(VerificationResult {
                        action_id: remaining.action_id.clone(),
                        permitted: false,
                        violations: vec![format!(
                            "Plan aborted: action '{}' triggered a sovereignty violation. \
                             Remaining plan cancelled.",
                            trigger_id
                        )],
                        warnings: vec![],
                        confidence: 0.0,
                        requires_human_arbitration: true,
                        manipulation_score: 0.0,
                        signature: None,
                        signing_key: None,
                        key_id: None,
                        timestamp: None,
                        nonce: None,
                    });
                }
                return Ok(results);
            }
        }
        Ok(results)
    }

    /// Verify action and attach an ed25519 signature to the result.
    pub fn verify_signed(
        &self,
        py: Python<'_>,
        action: PyRef<Action>,
    ) -> PyResult<VerificationResult> {
        let reg_w = {
            let reg = self.registry.borrow(py);
            let inner = reg.inner.lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
            registry_wire(&inner)
        };
        let mut r = crate::engine::verify(&reg_w, &action_wire(&action));
        crate::ffi::attach_signature(&mut r)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        let result = wire_to_result(r);
        if let Some(ref log) = self.audit_log {
            let result_obj = Py::new(py, result.clone())?;
            log.call_method1(py, "record", (result_obj,))?;
        }
        Ok(result)
    }
}

#![allow(clippy::useless_conversion)]
use std::collections::HashMap;
use std::sync::Mutex;

use pyo3::prelude::*;

use crate::entities::{AgentType, Entity, Resource, RightsClaim};

// ─── Internal pure-Rust storage (no PyObject, safe across threads) ────────────

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EntityKey {
    pub name: String,
    pub is_machine: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ResourceKey {
    pub name: String,
    pub rtype: String,
    pub scope: String,
    pub is_public: bool,
}

#[derive(Clone, Debug)]
pub struct ClaimEntry {
    pub holder: EntityKey,
    pub resource: ResourceKey,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delegate: bool,
    pub confidence: f64,
    pub expires_at: Option<f64>,
}

impl ClaimEntry {
    fn is_expired(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        self.expires_at
            .map(|t| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64()
                    > t
            })
            .unwrap_or(false)
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.confidence > 0.0
    }

    pub fn covers(&self, op: crate::capability::Operation) -> bool {
        if !self.is_valid() {
            return false;
        }
        match op {
            crate::capability::Operation::Read => self.can_read,
            crate::capability::Operation::Write => self.can_write,
            crate::capability::Operation::Delegate => self.can_delegate,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConflictEntry {
    pub resource: ResourceKey,
    pub claimant_a: EntityKey,
    pub claimant_b: EntityKey,
    pub description: String,
}

// ─── Python-facing ConflictRecord ─────────────────────────────────────────────

#[pyclass]
#[derive(Clone, Debug)]
pub struct ConflictRecord {
    inner: ConflictEntry,
}

#[pymethods]
impl ConflictRecord {
    #[getter]
    fn resource(&self) -> Resource {
        Resource::new(
            self.inner.resource.name.clone(),
            crate::entities::ResourceType::from_static(leak_str(&self.inner.resource.rtype)),
            Some(self.inner.resource.scope.clone()),
            self.inner.resource.is_public,
            None,
        )
    }

    #[getter]
    fn claimant_a(&self, py: Python<'_>) -> Entity {
        entity_from_key(py, &self.inner.claimant_a)
    }

    #[getter]
    fn claimant_b(&self, py: Python<'_>) -> Entity {
        entity_from_key(py, &self.inner.claimant_b)
    }

    #[getter]
    fn description(&self) -> &str {
        &self.inner.description
    }
}

fn entity_from_key(py: Python<'_>, key: &EntityKey) -> Entity {
    let kind = if key.is_machine {
        AgentType::Machine
    } else {
        AgentType::Human
    };
    Entity::new(py, key.name.clone(), kind, None)
}

/// Leak a String to get &'static str — only used for the small set of
/// known ResourceType values that are already compile-time constants.
fn leak_str(s: &str) -> &'static str {
    match s {
        "file" => "file",
        "api_endpoint" => "api_endpoint",
        "database_table" => "database_table",
        "network_endpoint" => "network_endpoint",
        "compute_slot" => "compute_slot",
        "message_channel" => "message_channel",
        "credential" => "credential",
        "model_weights" => "model_weights",
        "dataset" => "dataset",
        "memory_region" => "memory_region",
        _ => "file",
    }
}

// ─── RegistryInner ────────────────────────────────────────────────────────────

pub struct RegistryInner {
    pub claims: Vec<ClaimEntry>,
    pub machine_owners: HashMap<EntityKey, EntityKey>,
    pub conflicts: Vec<ConflictEntry>,
    pub conflict_hook: Option<PyObject>,
    pub frozen: bool,
}

impl RegistryInner {
    fn new() -> Self {
        RegistryInner {
            claims: Vec::new(),
            machine_owners: HashMap::new(),
            conflicts: Vec::new(),
            conflict_hook: None,
            frozen: false,
        }
    }

    fn detect_conflict(&self, new: &ClaimEntry) -> Option<ConflictEntry> {
        for existing in &self.claims {
            if existing.resource == new.resource
                && existing.holder != new.holder
                && existing.can_write
                && new.can_write
                && existing.is_valid()
            {
                return Some(ConflictEntry {
                    resource: new.resource.clone(),
                    claimant_a: existing.holder.clone(),
                    claimant_b: new.holder.clone(),
                    description: format!(
                        "Conflicting write claims on {}:{}: {} and {}",
                        new.resource.rtype,
                        new.resource.name,
                        existing.holder.name,
                        new.holder.name,
                    ),
                });
            }
        }
        None
    }

    pub fn can_act(&self, holder: &EntityKey, resource: &ResourceKey, op: crate::capability::Operation) -> (bool, f64, String) {
        if resource.is_public && op == crate::capability::Operation::Read {
            return (true, 1.0, "public resource".to_string());
        }
        let candidates: Vec<&ClaimEntry> = self
            .claims
            .iter()
            .filter(|c| &c.holder == holder && &c.resource == resource && c.covers(op))
            .collect();

        if candidates.is_empty() {
            return (
                false,
                0.0,
                format!(
                    "{} holds no valid {} claim on {}:{}",
                    holder.name, op, resource.rtype, resource.name
                ),
            );
        }
        let best_conf = candidates
            .iter()
            .map(|c| c.confidence)
            .fold(f64::NEG_INFINITY, f64::max);
        (true, best_conf, format!("claim confidence={:.2}", best_conf))
    }
}

// ─── Python-facing OwnershipRegistry ─────────────────────────────────────────

#[pyclass]
pub struct OwnershipRegistry {
    pub inner: Mutex<RegistryInner>,
}

pub fn entity_to_key(e: &Entity) -> EntityKey {
    EntityKey {
        name: e.name.clone(),
        is_machine: e.is_machine(),
    }
}

pub fn resource_to_key(r: &Resource) -> ResourceKey {
    ResourceKey {
        name: r.name.clone(),
        rtype: r.rtype.val.to_string(),
        scope: r.scope.clone(),
        is_public: r.is_public,
    }
}

#[pymethods]
impl OwnershipRegistry {
    #[new]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        OwnershipRegistry {
            inner: Mutex::new(RegistryInner::new()),
        }
    }

    /// Return an immutable snapshot. Mutations on the snapshot raise RuntimeError.
    pub fn freeze(&self) -> PyResult<OwnershipRegistry> {
        let inner = self.inner.lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
        let mut snapshot = RegistryInner::new();
        snapshot.claims = inner.claims.clone();
        snapshot.machine_owners = inner.machine_owners.clone();
        snapshot.conflicts = inner.conflicts.clone();
        snapshot.frozen = true;
        Ok(OwnershipRegistry { inner: Mutex::new(snapshot) })
    }

    pub fn set_conflict_hook(&self, hook: PyObject) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).conflict_hook = Some(hook);
    }

    pub fn add_claim(&self, py: Python<'_>, claim: PyRef<RightsClaim>) -> PyResult<()> {
        if self.inner.lock().map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?.frozen {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Registry is frozen; mutations are not permitted on snapshots."
            ));
        }
        let entry = ClaimEntry {
            holder: entity_to_key(&claim.holder),
            resource: resource_to_key(&claim.resource),
            can_read: claim.can_read,
            can_write: claim.can_write,
            can_delegate: claim.can_delegate,
            confidence: claim.confidence,
            expires_at: claim.expires_at,
        };

        let (conflict, hook) = {
            let mut inner = self.inner.lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
            let conflict = inner.detect_conflict(&entry);
            if let Some(ref c) = conflict {
                inner.conflicts.push(c.clone());
            }
            inner.claims.push(entry);
            (conflict, inner.conflict_hook.as_ref().map(|h| h.clone_ref(py)))
        };

        if let (Some(conflict_entry), Some(hook)) = (conflict, hook) {
            let record = ConflictRecord { inner: conflict_entry };
            let obj = Py::new(py, record)?;
            hook.call1(py, (obj,))?;
        }
        Ok(())
    }

    pub fn register_machine(
        &self,
        machine: PyRef<Entity>,
        owner: PyRef<Entity>,
    ) -> PyResult<()> {
        if self.inner.lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?.frozen {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Registry is frozen; mutations are not permitted on snapshots."
            ));
        }
        if !machine.is_machine() {
            return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "{} is not MACHINE.",
                machine.name
            )));
        }
        if !owner.is_human() {
            return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "{} is not HUMAN.",
                owner.name
            )));
        }
        let mk = entity_to_key(&machine);
        let ok = entity_to_key(&owner);
        self.inner.lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?
            .machine_owners.insert(mk, ok);
        Ok(())
    }

    pub fn owner_of(&self, py: Python<'_>, machine: PyRef<Entity>) -> Option<Entity> {
        let key = entity_to_key(&machine);
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.machine_owners.get(&key).map(|ok| {
            Entity::new(py, ok.name.clone(), AgentType::Human, None)
        })
    }

    pub fn can_act(
        &self,
        holder: PyRef<Entity>,
        resource: PyRef<Resource>,
        operation: &str,
    ) -> (bool, f64, String) {
        let hk = entity_to_key(&holder);
        let rk = resource_to_key(&resource);
        let op = match crate::capability::Operation::from_str(operation) {
            Some(op) => op,
            None => return (false, 0.0, format!("unknown operation: {}", operation)),
        };
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).can_act(&hk, &rk, op)
    }

    /// Delegate a claim from `delegated_by` to `claim.holder`.
    ///
    /// Enforces attenuation: delegated_by must hold a valid, delegatable claim on
    /// claim.resource, and the new claim cannot exceed the delegator's rights or confidence.
    pub fn delegate(
        &self,
        py: Python<'_>,
        claim: PyRef<RightsClaim>,
        delegated_by: PyRef<Entity>,
    ) -> PyResult<()> {
        if self.inner.lock().unwrap_or_else(|e| e.into_inner()).frozen {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Registry is frozen; mutations are not permitted on snapshots."
            ));
        }
        let delegator_key = entity_to_key(&delegated_by);
        let resource_key = resource_to_key(&claim.resource);

        let (best_read, best_write, best_delegate, best_conf) = {
            let inner = self.inner.lock()
                .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
            let candidates: Vec<&ClaimEntry> = inner
                .claims
                .iter()
                .filter(|c| {
                    c.holder == delegator_key
                        && c.resource == resource_key
                        && c.can_delegate
                        && c.is_valid()
                })
                .collect();

            if candidates.is_empty() {
                return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                    "Attenuation violation: {} holds no valid delegatable claim on {}:{}. \
                     Cannot delegate to {}.",
                    delegated_by.name,
                    resource_key.rtype,
                    resource_key.name,
                    claim.holder.name,
                )));
            }

            // fold avoids unwrap on partial_cmp (NaN safety) and on Option from max_by.
            let mut best_r = false;
            let mut best_w = false;
            let mut best_d = false;
            let mut best_c = f64::NEG_INFINITY;
            for c in &candidates {
                if c.confidence > best_c {
                    best_c = c.confidence;
                    best_r = c.can_read;
                    best_w = c.can_write;
                    best_d = c.can_delegate;
                }
            }
            (best_r, best_w, best_d, best_c)
        };

        if claim.can_read && !best_read {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                "Attenuation: {} cannot delegate read on {}:{} (delegator lacks read).",
                delegated_by.name, resource_key.rtype, resource_key.name,
            )));
        }
        if claim.can_write && !best_write {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                "Attenuation: {} cannot delegate write on {}:{} (delegator lacks write).",
                delegated_by.name, resource_key.rtype, resource_key.name,
            )));
        }
        if claim.can_delegate && !best_delegate {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                "Attenuation: {} cannot sub-delegate {}:{} (delegator lacks delegate).",
                delegated_by.name, resource_key.rtype, resource_key.name,
            )));
        }
        if claim.confidence > best_conf + 1e-9 {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                "Attenuation: confidence {:.2} exceeds {}'s {:.2} on {}:{}.",
                claim.confidence, delegated_by.name, best_conf,
                resource_key.rtype, resource_key.name,
            )));
        }

        // All checks passed — add the claim (with conflict detection, same as add_claim)
        self.add_claim(py, claim)
    }

    pub fn open_conflicts(&self, py: Python<'_>) -> PyResult<Vec<PyObject>> {
        let inner = self.inner.lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("kernel lock poisoned"))?;
        let mut result = Vec::new();
        for entry in &inner.conflicts {
            let record = ConflictRecord { inner: entry.clone() };
            result.push(Py::new(py, record)?.into_any());
        }
        Ok(result)
    }

    pub fn claims_for(
        &self,
        holder: PyRef<Entity>,
        resource: PyRef<Resource>,
    ) -> Vec<RightsClaim> {
        let hk = entity_to_key(&holder);
        let rk = resource_to_key(&resource);
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .claims
            .iter()
            .filter(|c| c.holder == hk && c.resource == rk && c.is_valid())
            .map(|c| RightsClaim::new(
                holder.clone(),
                resource.clone(),
                c.can_read,
                c.can_write,
                c.can_delegate,
                c.confidence,
                c.expires_at,
            ))
            .collect()
    }
}

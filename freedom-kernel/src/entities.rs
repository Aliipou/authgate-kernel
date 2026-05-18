#![allow(clippy::useless_conversion)]
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// ─── AgentType ────────────────────────────────────────────────────────────────

#[pyclass(eq, hash, frozen)]
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AgentType {
    Human,
    Machine,
}

#[pymethods]
impl AgentType {
    /// AgentType.HUMAN — matches Python convention
    #[classattr]
    #[allow(non_snake_case)]
    fn HUMAN() -> AgentType {
        AgentType::Human
    }

    /// AgentType.MACHINE — matches Python convention
    #[classattr]
    #[allow(non_snake_case)]
    fn MACHINE() -> AgentType {
        AgentType::Machine
    }

    /// The string name, e.g. "HUMAN"
    #[getter]
    fn name(&self) -> &'static str {
        match self {
            AgentType::Human => "HUMAN",
            AgentType::Machine => "MACHINE",
        }
    }

    fn __str__(&self) -> &'static str {
        self.name()
    }

    fn __repr__(&self) -> String {
        format!("<AgentType.{}>", self.name())
    }
}

// ─── ResourceType ─────────────────────────────────────────────────────────────

/// Maps a resource type string value ("file", "compute_slot", …) to a canonical
/// constant. Supports Python-style `ResourceType("file")` construction.
#[pyclass(frozen)]
#[derive(Clone, Debug)]
pub struct ResourceType {
    pub(crate) val: &'static str,
}

impl PartialEq for ResourceType {
    fn eq(&self, other: &Self) -> bool {
        self.val == other.val
    }
}
impl Eq for ResourceType {}
impl Hash for ResourceType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.val.hash(state);
    }
}

impl ResourceType {
    pub fn from_static(val: &'static str) -> Self {
        ResourceType { val }
    }
}

#[pymethods]
impl ResourceType {
    /// `ResourceType("file")` — matches Python enum(value) construction
    #[new]
    fn new(value: &str) -> PyResult<Self> {
        match value {
            "file" => Ok(ResourceType { val: "file" }),
            "api_endpoint" => Ok(ResourceType { val: "api_endpoint" }),
            "database_table" => Ok(ResourceType { val: "database_table" }),
            "network_endpoint" => Ok(ResourceType { val: "network_endpoint" }),
            "compute_slot" => Ok(ResourceType { val: "compute_slot" }),
            "message_channel" => Ok(ResourceType { val: "message_channel" }),
            "credential" => Ok(ResourceType { val: "credential" }),
            "model_weights" => Ok(ResourceType { val: "model_weights" }),
            "dataset" => Ok(ResourceType { val: "dataset" }),
            "memory_region" => Ok(ResourceType { val: "memory_region" }),
            _ => Err(PyValueError::new_err(format!(
                "'{}' is not a valid ResourceType value",
                value
            ))),
        }
    }

    /// String value, e.g. "file"
    #[getter]
    fn value(&self) -> &str {
        self.val
    }

    fn __str__(&self) -> &str {
        self.val
    }
    fn __repr__(&self) -> String {
        format!("<ResourceType '{}'>", self.val)
    }
    fn __eq__(&self, other: &ResourceType) -> bool {
        self.val == other.val
    }
    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.val.hash(&mut h);
        h.finish()
    }

    // ── class-level constants ─────────────────────────────────────────────────
    #[classattr]
    #[allow(non_snake_case)]
    fn FILE() -> ResourceType { ResourceType { val: "file" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn API_ENDPOINT() -> ResourceType { ResourceType { val: "api_endpoint" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn DATABASE_TABLE() -> ResourceType { ResourceType { val: "database_table" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn NETWORK_ENDPOINT() -> ResourceType { ResourceType { val: "network_endpoint" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn COMPUTE_SLOT() -> ResourceType { ResourceType { val: "compute_slot" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn MESSAGE_CHANNEL() -> ResourceType { ResourceType { val: "message_channel" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn CREDENTIAL() -> ResourceType { ResourceType { val: "credential" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn MODEL_WEIGHTS() -> ResourceType { ResourceType { val: "model_weights" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn DATASET() -> ResourceType { ResourceType { val: "dataset" } }
    #[classattr]
    #[allow(non_snake_case)]
    fn MEMORY_REGION() -> ResourceType { ResourceType { val: "memory_region" } }
}

// ─── Resource ─────────────────────────────────────────────────────────────────

#[pyclass(frozen)]
#[derive(Clone, Debug)]
pub struct Resource {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub rtype: ResourceType,
    #[pyo3(get)]
    pub scope: String,
    #[pyo3(get)]
    pub is_public: bool,
    #[pyo3(get)]
    pub ifc_label: String,
}

// ifc_label is metadata — excluded from PartialEq/Hash (matches Python compare=False, hash=False)
impl PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.rtype == other.rtype
            && self.scope == other.scope
            && self.is_public == other.is_public
    }
}
impl Eq for Resource {}
impl Hash for Resource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.rtype.hash(state);
        self.scope.hash(state);
        self.is_public.hash(state);
    }
}

#[pymethods]
impl Resource {
    #[new]
    #[pyo3(signature = (name, rtype, scope = None, is_public = false, ifc_label = None))]
    pub fn new(
        name: String,
        rtype: ResourceType,
        scope: Option<String>,
        is_public: bool,
        ifc_label: Option<String>,
    ) -> Self {
        Resource {
            name,
            rtype,
            scope: scope.unwrap_or_default(),
            is_public,
            ifc_label: ifc_label.unwrap_or_default(),
        }
    }

    fn __str__(&self) -> String {
        format!("{}:{}", self.rtype.val, self.name)
    }
    fn __repr__(&self) -> String {
        format!("Resource(name={:?}, rtype={:?})", self.name, self.rtype.val)
    }
    fn __eq__(&self, other: &Resource) -> bool {
        self == other
    }
    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

// ─── Entity ───────────────────────────────────────────────────────────────────

#[pyclass(frozen)]
#[derive(Debug)]
pub struct Entity {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub kind: AgentType,
    metadata: PyObject,
}

impl Clone for Entity {
    fn clone(&self) -> Self {
        Python::with_gil(|py| Entity {
            name: self.name.clone(),
            kind: self.kind.clone(),
            metadata: self.metadata.clone_ref(py),
        })
    }
}

// Equality/hash exclude metadata (matches Python frozen dataclass behaviour)
impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.kind == other.kind
    }
}
impl Eq for Entity {}
impl Hash for Entity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.kind.hash(state);
    }
}

#[pymethods]
impl Entity {
    #[new]
    #[pyo3(signature = (name, kind, metadata = None))]
    pub fn new(
        py: Python<'_>,
        name: String,
        kind: AgentType,
        metadata: Option<PyObject>,
    ) -> Self {
        Entity {
            name,
            kind,
            metadata: metadata.unwrap_or_else(|| py.None().into()),
        }
    }

    #[getter]
    fn metadata(&self, py: Python<'_>) -> PyObject {
        self.metadata.clone_ref(py)
    }

    pub fn is_human(&self) -> bool {
        self.kind == AgentType::Human
    }
    pub fn is_machine(&self) -> bool {
        self.kind == AgentType::Machine
    }

    fn __str__(&self) -> String {
        format!("{}({})", self.kind.name(), self.name)
    }
    fn __repr__(&self) -> String {
        format!("Entity(name={:?}, kind={:?})", self.name, self.kind.name())
    }
    fn __eq__(&self, other: &Entity) -> bool {
        self == other
    }
    fn __hash__(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

// ─── RightsClaim ──────────────────────────────────────────────────────────────

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct RightsClaim {
    #[pyo3(get, set)]
    pub holder: Entity,
    #[pyo3(get, set)]
    pub resource: Resource,
    #[pyo3(get, set)]
    pub can_read: bool,
    #[pyo3(get, set)]
    pub can_write: bool,
    #[pyo3(get, set)]
    pub can_delegate: bool,
    #[pyo3(get, set)]
    pub confidence: f64,
    #[pyo3(get, set)]
    pub expires_at: Option<f64>,
}

#[pymethods]
impl RightsClaim {
    #[new]
    #[pyo3(signature = (
        holder,
        resource,
        can_read = true,
        can_write = false,
        can_delegate = false,
        confidence = 1.0,
        expires_at = None,
    ))]
    pub fn new(
        holder: Entity,
        resource: Resource,
        can_read: bool,
        can_write: bool,
        can_delegate: bool,
        confidence: f64,
        expires_at: Option<f64>,
    ) -> Self {
        RightsClaim {
            holder,
            resource,
            can_read,
            can_write,
            can_delegate,
            confidence,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|t| now_secs() > t)
            .unwrap_or(false)
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.confidence > 0.0
    }

    pub fn covers(&self, operation: &str) -> bool {
        if !self.is_valid() {
            return false;
        }
        match operation {
            "read" => self.can_read,
            "write" => self.can_write,
            "delegate" => self.can_delegate,
            _ => false,
        }
    }
}

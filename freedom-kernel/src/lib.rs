#![allow(unexpected_cfgs)]
#![allow(clippy::useless_conversion)]
pub mod authority_graph;
pub mod capability;
mod crypto;
pub(crate) mod engine;
pub mod entities;
pub mod ffi;
pub mod goal_tree;
#[cfg(kani)]
mod kani_proofs;
pub mod multi_agent;
pub mod planner;
pub mod registry;
pub mod verifier;
#[cfg(feature = "wasm")]
pub mod wasm;
pub mod wire;

use pyo3::prelude::*;

use crate::entities::{AgentType, Entity, Resource, ResourceType, RightsClaim};
use crate::registry::{ConflictRecord, OwnershipRegistry};
use crate::verifier::{Action, FreedomVerifier, VerificationResult};

/// Verify an action against a registry using the JSON wire format.
///
/// `input_json` must be:
///   `{"registry": <OwnershipRegistryWire>, "action": <ActionWire>}`
///
/// Returns a JSON string (`VerificationResultWire`) with an ed25519 signature.
/// Works identically to `FreedomVerifier.verify_signed()` but speaks pure JSON —
/// usable from any language that can call the Python extension or the C ABI.
#[pyfunction]
fn verify_json(input_json: &str) -> PyResult<String> {
    let vi: crate::wire::VerifyInput = serde_json::from_str(input_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let mut r = crate::engine::verify(&vi.registry, &vi.action);
    crate::ffi::attach_signature(&mut r)
        .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
    serde_json::to_string(&r)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Return this kernel instance's ed25519 verifying key (hex, 64 chars).
///
/// Any party that holds the public key can verify signatures on
/// `VerificationResult.signature` without trusting the calling process.
#[pyfunction]
fn kernel_pubkey() -> String {
    crate::crypto::pubkey_hex()
}

#[pymodule]
fn authgate_kernel(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AgentType>()?;
    m.add_class::<ResourceType>()?;
    m.add_class::<Resource>()?;
    m.add_class::<Entity>()?;
    m.add_class::<RightsClaim>()?;
    m.add_class::<ConflictRecord>()?;
    m.add_class::<OwnershipRegistry>()?;
    m.add_class::<Action>()?;
    m.add_class::<VerificationResult>()?;
    m.add_class::<FreedomVerifier>()?;
    m.add_function(wrap_pyfunction!(verify_json, m)?)?;
    m.add_function(wrap_pyfunction!(kernel_pubkey, m)?)?;
    Ok(())
}

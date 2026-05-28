/// TCB — Trusted Computing Base.
///
/// Everything in this module is subject to formal verification (Kani + Lean 4).
/// Everything outside this module is UNTRUSTED — adapters, FFI, registry, verifier.
///
/// # TCB surface area (intentionally minimal)
/// - `types`     — data types only; zero logic, zero IO
/// - `dag`       — delegation chain validation
/// - `call_gate` — the ONLY public entry point into the kernel (AT-7.5 closure)
/// - `sequence`  — composition safety: tracks accumulated rights across an action sequence
/// - `engine`    — `pub(crate)` verify(); reachable only through `call_gate`
///
/// # Public API surface
/// External callers use `CallGate::execute()`. The `engine::verify` function is
/// `pub(crate)` — it is a compile-time type error to call it from outside this crate.
///
/// # Invariants enforced here (see formal/lean4/Invariants.lean for proofs)
/// - INV-ATTENUATION: child.rights ⊆ parent.rights in every chain
/// - INV-SUBJECT:     capability.subject_id == action.actor_id
/// - INV-RESOURCE:    capability.resource_hash == action.resource_hash
/// - INV-EXPIRY:      capability.expiry >= now
/// - INV-EPOCH:       capability.epoch >= action.min_epoch
/// - INV-SIGCHAIN:    every node in the chain has a valid ed25519 signature
/// - INV-ROOTSIG:     the chain root is verified against the caller-supplied root key
/// - INV-CANONICAL:   action.binding_hash == H(all other fields) before any processing
/// - INV-REVOCATION:  only root-signed revocations affect permit/deny decisions
pub mod call_gate;
pub mod dag;
pub mod sequence;
pub mod types;
pub(crate) mod engine;
#[cfg(test)]
mod tests;

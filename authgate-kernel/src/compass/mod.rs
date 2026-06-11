#![forbid(unsafe_code)]
//! Mahdavi Compass — computable post-hoc scorer (Gap 3).
//!
//! NOT in the TCB. Post-hoc scorer — annotates, never denies.
//! The deny threshold is operator policy, not theory.
//!
//! The Compass scores an action *after the fact* along three dimensions of
//! the Theory of Freedom:
//!
//! * **RVD** — rights violations decrease
//! * **VOI** — voluntary order increases
//! * **CD**  — coercion (irreversibility) decreases
//!
//! `C(a) = w1*RVD + w2*VOI + w3*CD`, equal default weights (1/3 each),
//! configurable via [`metric::CompassWeights`]. A negative score is an
//! *annotation* (`compass_negative = true`); whether anything is flagged or
//! denied on that basis is entirely an operator decision made downstream.

pub mod metric;
pub mod violation_registry;
#[cfg(test)]
mod redteam;

pub use metric::{
    annotate, coercion_decreases, flagged_below, rights_violations_decrease, score,
    voluntary_order_increases, CompassInput, CompassScore, CompassWeights, GuidanceAnnotation,
};
pub use violation_registry::{ViolationEntry, ViolationRegistry, ViolationType};

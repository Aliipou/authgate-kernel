# Decisions

Architectural decision records. See CLAUDE.md §7 for the format.

## 2026-08-21 — Rename FDK → legitimacy; keep decision-os composition

**Context:** FDK as a product/theory brand was closed. Freedom Formal (skill A1–A5)
is the research legitimacy engine. We needed one name and one composition model
without folding norms into the AuthGate TCB.

**Decision:**
- Rename the seam module to `authgate.integrations.legitimacy` (FDK kept as
  re-export shim).
- Keep **decision-os composition**: lattice meet; legitimacy is DENY-only and
  never grants; AuthGate CallGate alone decides authority (TCB unchanged).
- Default legitimacy engine on legitimacy-enabled branches: Freedom Formal
  (`decide_freedom_formal` / `enforce_freedom_formal`).
- Branch line: `main` = AuthGate without legitimacy required;
  `with-legitimacy` / `research/freedom-fullscope` = AuthGate + legitimacy seam.

**Reason:** One product brand (AuthGate), one optional veto plugin (legitimacy),
replaceable evaluator behind the existing PolicyDecision contract.

**Trade-offs accepted:** Extra branch/docs surface; FDK name remains as shim
until external callers migrate.

**Revisit when:** Real deployments show legitimacy false-positives dominate, or
a subset of checks deserves a proven TCB bit (still not a full Rust FDK port).

## 2026-06-18 — FDK↔AuthGate boundary: a JSON contract, not shared code

**Context:** FDK (Freedom Decision Kernel) and AuthGate both touch
ownership/consent concepts and risked overlapping. We needed the two to compose
into one product — `Request → Planner → FDK → AuthGate → TCB → Execution` —
without coupling them or duplicating responsibility.

**Decision:** Split responsibility cleanly and connect them through a single
serialisable contract:
- **FDK** answers *"is this action legitimate?"* and emits a `PolicyDecision`
  (`spec/policy_decision.schema.json`): `verdict` ∈ {ALLOW, DENY, DEFER},
  `action_id`, `reasons`, `axiom_trace`, `fail_closed`.
- **AuthGate** answers *"can this actor execute it?"* (capability + scope +
  signature + TCB) and consumes the contract via `authgate.integrations.fdk`.
- The seam (`enforce_legitimacy`) runs the `CallGate` **only** on an explicit
  ALLOW bound to the same `action_id`; everything else (DENY, DEFER,
  `fail_closed`, malformed payload, id mismatch) is fail-closed → no execution.
- `authgate.integrations.fdk` imports **no FDK code.** The contract is the only
  coupling.

**Reason:** A shared schema (not shared code) keeps each side independently
deployable, testable, and replaceable, and removes the production-ambiguity of
two systems both claiming ownership logic. AuthGate stays the single source of
truth for authority; FDK only *interprets* legitimacy. Ambiguity is the enemy in
production — this draws the line where it belongs.

**Trade-offs accepted:** The two repos must keep the `PolicyDecision` schema in
sync by hand (no generated stubs). We deliberately omit a `confidence` field:
FDK is a deterministic, categorical gate, so a probability would re-introduce the
ambiguity we are removing — `DEFER` already means "unsure, ask a human."

**Revisit when:** a second upstream decider needs the seam (generalise
`integrations/`), or the contract needs a breaking change (bump
`policy_decision.schema.json` + both sides).

## 2026-09-16 — Made `pyo3` optional so the documented `wasm` build actually works

**Context:** `authgate-kernel/Cargo.toml` documented a `wasm` feature and a
`wasm-pack build --target web -- --features wasm` command in its own comments,
but running that command failed: `pyo3` (the Python extension-module binding)
was a mandatory dependency, and pyo3's build script cannot cross-compile to
`wasm32-unknown-unknown` without a Python-for-wasm toolchain this crate has no
use for. The documented build path had never actually been exercised.

**Decision:** Made `pyo3` `optional = true`, added a `python` feature (on by
default, so every existing native/Python build and test keeps working exactly
as before) that gates it, and moved the pyo3-facing module (`authgate_kernel`
pymodule, `verify_json`, `kernel_pubkey`) into a `#[cfg(feature = "python")]`
block in `lib.rs`. Also gated `entities.rs`, `registry.rs`, `verifier.rs`
(the pyo3-`#[pyclass]`-heavy "v1" Python-facing modules — confirmed via grep
that nothing in `tcb/`, `engine.rs`, `wire.rs`, or `wasm.rs` depends on them)
behind the same feature, since they don't compile without pyo3 either.
Also added `getrandom = { features = ["js"] }` scoped to `cfg(target_arch =
"wasm32")` — `getrandom` (pulled in transitively via `rand_core`/
`ed25519-dalek`) refuses to build for wasm32 unless told which randomness
source to use in a browser.

**Reason:** This is exactly what the crate's own doc comments already
described as the intended architecture (`wasm.rs`'s own header: "The WASM
build uses only `engine.rs` and `wire.rs` — no PyO3") — the Cargo.toml just
hadn't been wired to actually make that true. Verified with `cargo build
--target wasm32-unknown-unknown --no-default-features --features wasm --lib`
(succeeds) and a plain `cargo build --lib` (unchanged, still succeeds,
Python bindings intact).

**Trade-offs accepted:** None known — this only removes a dependency from
builds that never needed it.

**Revisit when:** If `entities.rs`/`registry.rs`/`verifier.rs` (the "v1"
Python-facing API) ever need to be reachable from a non-Python build target.

## 2026-09-16 — Fix a time-bomb test in `session_clock.rs`

**Context:** After merging `with-legitimacy` to `main`, `cargo test --release`
showed 2 failures: `accept_rejects_backward_jump` and
`accept_allows_equal_and_forward`. Both called `SessionClock::new()` (which
anchors `last` to real `SystemTime::now()`) and then immediately called
`.accept()` with a hardcoded absolute past timestamp (`100`, `1_700_000_000`
— November 2023) as if `last` started at 0. That passed only while real wall
time stayed behind those hardcoded values; it doesn't anymore (it's 2026).

**Decision:** Rewrote both tests to anchor to `clock.last()` (the real value
`SessionClock::new()` actually produces) and assert relative offsets from it,
instead of hardcoded absolute Unix timestamps. Production code
(`session_clock.rs`'s `accept`/`now`) was not touched — the backward-jump
rejection logic is correct; only the tests were time-bombed.

**Reason:** This is a test-design bug, not a product bug, and the fix
preserves the exact semantics under test (reject strictly-backward, accept
equal/forward) without depending on the wall clock never passing a fixed
point. Verified: `cargo test --release` — 300 passed, 0 failed (was 298
passed, 2 failed).

**Trade-offs accepted:** None.

**Revisit when:** N/A — this makes the test immune to further clock drift by
construction.

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

## 2026-09-16 — Close the consent-semantics gap with an untrusted veto, document why the God→Human gap should stay open

**Context:** PHILOSOPHY/COVERAGE_MATRIX.md names two gaps: row 8 (Consent
Logic) reports `informed`/`voluntary`/`competent`/`not-deceived` as required
by the theory but not computed; row 20 (`God -> Human`) reports the
ontological root as not modeled. Asked to work through documented gaps and
close what's actually closeable.

**Decision:**
- Added `extensions/consent_semantics.py`: `semantic_consent_veto`, the same
  architecture as the sibling `decision-os-min` project's `semantic_veto`
  (reused defenses line for line) — an optional, untrusted judge composed
  outside `kernel/`, veto-only, fail-closed on every error path, contributing
  no evidence. Closes row 8's actual computational gap without putting
  semantic vocabulary in the TCB (TCB_DISCIPLINE Rule 2). Row 8 stays
  **Partial** on purpose — a judge's permit is not a mechanical guarantee.
- Did **not** attempt to close row 20 the same way. Wrote
  `PHILOSOPHY/GOD_HUMAN_BOUNDARY.md` instead, arguing the two gaps are
  different in kind: row 8 is a coverage gap (a judgeable predicate nobody
  computed yet); row 20 is a category boundary (`Person(h) -> OwnedByGod(h)`
  is not the kind of claim any formal system, this one included, can verify
  from within itself — the general-purpose version of this is already stated
  in `formal/lean4/FreedomKernel/Incompleteness.lean`'s "Axiom Soundness"
  section for A1–A7; this file makes the same argument explicit one level up,
  for the root those axioms protect). Marked row 20 "Documented gap,
  permanently" rather than leaving it looking like unfinished work.

**Reason:** Comprehensiveness for a system that also has to stay
non-contradictory means treating mechanically-checkable claims, judgeable-
but-not-provable claims, and undefended axioms as three different categories
and being honest about which is which — not writing code against the third
category to make the coverage table look more finished than the system
actually is.

**Trade-offs accepted:** `semantic_consent_veto` has no timeout of its own
(this codebase has no single host applying `evaluator_timeout_s` uniformly
the way decision-os-min's `DecisionOS`/`Governor`/`AgentHost` do) — a caller
wiring it into a real-time pipeline must bound the judge call themselves.
Documented in `docs/CONSENT_SEMANTICS.md` rather than solved here.

**Revisit when:** If this codebase grows a single composition host analogous
to decision-os-min's, give `semantic_consent_veto` the same timeout
enforcement rather than leaving it caller-responsibility.

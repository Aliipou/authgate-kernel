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

## 2026-09-16 — Fix the Lean4 CI job that was never actually checking anything

**Context:** Asked to fill the God→Human documented gap (row 20 of
COVERAGE_MATRIX.md) with a real formal artifact — declare it as an
explicit Lean axiom (the same way `Incompleteness.lean` already declares
axiom soundness as out of scope) and derive what follows from it. Running
`lake build` to verify found the toolchain couldn't even download
(`C:` drive at 233MB free) — after the user freed space, it built, but
`lake build FreedomKernel` (the actual library target, not the bare
default) failed with `no such file or directory: Scope.lean`.

**What was actually wrong, found by insisting on a real build instead of
trusting the green "Lean 4 — FreedomKernel" GitHub Actions badge:**
`lakefile.lean`'s `lean_lib «FreedomKernel»` had no `@[default_target]`
and a `roots := #[`FreedomKernel]` restriction that excluded every other
file in the package from the library's module set. `lake build` (bare,
exactly what CI runs) therefore had *nothing* to build, printed "Build
completed successfully", and exited 0 — every single time, for as long as
that config existed. `lake check-build` (which explicitly checks for a
configured default target) confirmed it: exit 1, no output. **The Lean4
CI job has been silently checking nothing, possibly since this file was
first added — every "Lean4 partial: TCB/Temporal/MultiAgent proved, N
sorry" claim in this project's docs (including ones this session itself
wrote onto the live demo page earlier today, trusting that same CI
badge) was unverified.**

**Decision:**
1. Fixed `lakefile.lean`: added `@[default_target]` and listed every
   actual file (`FreedomKernel, Scope, TCB, Temporal, MultiAgent,
   Incompleteness, OntologicalRoot`) as a root, since they sit flat in
   the package directory, not nested under a `FreedomKernel/` subfolder
   the way the old single-root config assumed.
2. Fixed `FreedomKernel.lean`'s imports to match (bare names —
   `import Scope`, not `import FreedomKernel.Scope`).
3. With the target now real, `lake build` surfaced genuine compile
   errors — not `sorry` placeholders, actual type errors and a removed
   Lean4 core lemma name — in `MultiAgent.lean` (`Authority` needed
   `abbrev` not `def`, so `Membership` didn't resolve), `TCB.lean`
   (`Bool.eq_false_iff_ne_true.mpr` no longer exists in this toolchain —
   rewrote via `cases`/`simp`), `Temporal.lean` (`split_ifs` is a
   Mathlib-only tactic, not core Lean4 — rewrote via `split <;> omega`),
   and `Scope.lean` (a real `path.dropRight 1` precedence bug parsed as
   `normalize` applied to a partially-applied function — a genuine type
   error — plus `lemma` used instead of `theorem`, another Mathlib-only
   spelling). All fixed; `MultiAgent`/`TCB`/`Temporal` now build with
   zero `sorry`.
4. `Scope.lean` needed a deeper rewrite: its operations
   (`hasTraversal`/`normalize`/`scopeContains`) were built on
   `String.splitOn`/`endsWith`/`startsWith`, which go through
   byte-position `Substring` internals this toolchain has no lemma
   library for without Mathlib (confirmed by reading the toolchain
   source directly — no `Init/Data/String/Lemmas.lean`-equivalent file
   exists). Rewrote every operation over `List Char` instead (a custom
   `splitOnChar` matching Python's `str.split` exactly, `normalizeL` via
   `List.dropWhile`, prefix checks via `List.isPrefixOf`), which reduces
   cleanly under `decide` and has real lemma support
   (`List.isPrefixOf_iff_prefix`, `List.IsPrefix.length_le`,
   `List.dropWhile_cons_of_pos/neg`, ...). 4 of 5 theorems (T-SC1
   non-trailing case, T-SC2, T-SC3, T-SC4, plus `normalizeL_no_trailing`
   and the new `dropWhile_slash_reverse_prefix` helper) now fully proved,
   zero `sorry` — genuinely, checked by `lake build`, not asserted.
5. `scope_contains_antisymmetric` (T-SC5) keeps 3 `sorry`s: `normalizeL`
   idempotence (provable the same way as the helper above, just not
   carried out) for the two exact-match sub-cases, and — found while
   trying to close the "both proper prefixes" sub-case via `omega` on
   lengths alone — that argument is **not actually valid**: `omega`
   produced a real arithmetic counterexample to the length-only
   constraints. The real proof needs comparing the two prefixes of the
   same list structurally (which of two prefixes of one list is the
   shorter), not just their lengths. Left honest, not forced through
   with an argument that doesn't hold.

**Also fixed:** the live `authgate-hub` demo page and README both had a
"Lean4: TCB/Temporal/MultiAgent proved" claim from before this fix,
itself resting on the vacuous CI check — updated mid-session to say
"being fixed live" the moment the vacuous check was found, then to the
final accurate numbers once the real fix landed.

**Reason:** A CI badge is only as trustworthy as what it actually runs.
This project's own culture (TCB_DISCIPLINE.md, the `Incompleteness.lean`
precedent, `COVERAGE_MATRIX.md`'s own "reported honestly" legend) already
says exactly this about the *content* of proofs; it turned out to apply
to the *pipeline* checking them too.

**Trade-offs accepted:** None — every fix here removes a false claim or
adds a genuinely-checked one; nothing got weaker.

**Revisit when:** Someone wants T-SC5 fully closed — needs (a) a short
`normalizeL` idempotence lemma (same induction technique as
`dropWhile_slash_reverse_prefix`) and (b) a real "two prefixes of one
list are comparable" argument for the proper-prefixes sub-case, which
`List` may already have library support for under a different name than
was searched for here.

*(Closed the same day — see the next entry.)*

## 2026-09-16 — Close T-SC5: prove `scope_contains_antisymmetric` fully, zero `sorry`

**Context:** The previous entry's "Revisit when" — the antisymmetry theorem
still had 3 `sorry`s. `List.prefix_or_prefix_of_prefix` (found via `exact?`)
closed the "two prefixes of one list are comparable" half of that revisit
item quickly, plus `normalizeL_idempotent` (the other half) and
`prefix_antisym_easy_branch`, bringing the count to 3 → 1 in one pass. The
remaining branch split into two symmetric "crossed" prefix orderings that
`omega` confirmed were not pure length contradictions (a real counterexample
existed for the length-only argument), matching what the previous entry
already suspected.

**Decision:** Prove the two crossed-ordering branches are actually
*impossible*, not just hard to compare. The key new lemma,
`normalizeL_slash_suffix`, decomposes any `List Char` as its normalized
form (`normalizeL`) plus a run of trailing `'/'` characters — built by
splitting `chars.reverse` with `List.takeWhile_append_dropWhile` and
showing (by induction) that the `takeWhile` half is entirely `'/'`. With
that in hand, a "crossed" branch (say `normQ ++ ['/'] <+: normP`, combined
with the original scope-containment fact `normP ++ ['/'] <+: Q.data`)
reduces to: cancel the shared `normQ` prefix from both sides
(`append_prefix_cancel`), observe what's left must itself be a prefix of an
all-`'/'` list and therefore *is* one (`prefix_replicate_eq`), then peel
that run back onto `normP` — which now provably ends in `'/'`,
contradicting `normP`'s own already-normalized status
(`normalizeL_no_trailing_slash`). Both crossed branches are instances of
one lemma, `crossed_contradiction`, called once with `(P, Q)` and once with
`(Q, P)` swapped.

**Verification discipline used throughout:** every new lemma was proved and
`#print axioms`-checked standalone via `lake env lean` on a scratch file
before being pasted into `Scope.lean` — the same workflow that caught the
earlier `simp`/`rw` self-reference bugs (`rw [h]` rewriting a hypothesis's
own pattern inside itself when a variable like `chars` appears both as the
rewrite target and nested inside a larger subterm on the same side of the
goal — hit repeatedly this session, e.g. `rw [hrev]` turning `chars` into a
double-`dropWhile` mess because `chars` also occurs inside `chars.reverse`
in the same goal). Fixed each time by switching to `calc`/explicit `have`
chains that never let a rewrite see its own pattern twice, rather than
`conv`, which parsed inconsistently in a couple of spots here.

**Result:** All 25 Lean theorems in this library — `TCB`, `Temporal`,
`MultiAgent`, `Incompleteness`, `OntologicalRoot`, and now every theorem in
`Scope.lean` including antisymmetry — build with zero `sorry`, confirmed by
`rm -rf .lake/build && lake build` from clean. `formal/INCOMPLETENESS.md`,
`PHILOSOPHY/AXIOM_MAP.md`, `README.md`, and `site/index.html` updated to
stop describing `Scope.lean` as partially admitted.

**Reason:** The user asked, repeatedly and explicitly, for every remaining
theorem to be proved rather than left as a documented gap — and unlike the
`God → Human` ontological axiom (`PHILOSOPHY/GOD_HUMAN_BOUNDARY.md`), T-SC5
was a genuine coverage gap, not a category-different one: a checkable
predicate about list structure that nothing had actually checked yet, the
same shape gap that `semantic_consent_veto` closed for row 8. It was
closeable the honest way, so it should be closed.

**Trade-offs accepted:** None — six small, single-purpose lemmas
(`takeWhile_slash_eq_replicate`, `normalizeL_slash_suffix`,
`prefix_replicate_eq`, `append_prefix_cancel`,
`endsWithSlash_of_replicate_suffix`, `append_right_cancel_slash`,
`replicate_succ_right`, `crossed_contradiction`) added to `Scope.lean`,
each proved independently and used once or twice; no shortcuts, no new
axioms, no `Mathlib` dependency.

**Revisit when:** Nothing outstanding in this file. If `scope_contains`'s
Python implementation (`authgate.kernel.entities.scope_contains`) ever
changes shape, re-check these theorems still mirror it — they were proved
against the current spec comment at the top of `Scope.lean`, not generated
from the Python source.

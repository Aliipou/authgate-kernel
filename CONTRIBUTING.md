# Contributing

## The one constitutional rule

Before anything else:

> **Can this feature exist entirely outside `engine.rs`?**

If yes — it does not belong in `engine.rs`. Full stop.

`engine.rs` is the TCB. Its value comes from being small, deterministic, and formally verifiable.
Every line added to it is a line that must be formally verified or it weakens the entire system.
A 200-line TCB is worth something. A 2000-line TCB is worth nothing.

See [`TCB.md`](TCB.md) for the full boundary definition.

---

## What we accept

### Outside the TCB (extensions/, adapters/, new modules)

- New adapters for LLM frameworks (OpenAI, Anthropic, LangChain, AutoGen, etc.)
- New extension layers (new heuristic detectors, conflict strategies, policy engines)
- New language bindings (TypeScript, Java, Swift, etc.)
- New integration examples
- Bug fixes in extensions
- Documentation improvements

### Inside the TCB (engine.rs, capability.rs, wire.rs, crypto.rs)

Very rarely, and only when:
- The change enforces a new formally-stated invariant
- The change cannot exist anywhere else by construction (not just convenience)
- The change keeps engine.rs ≤ 300 LOC
- The change adds zero interpretation, heuristics, or non-determinism

**Examples of TCB-eligible changes:**
- Adding a new typed `CapabilityKind` variant (one line, algebra only)
- Fixing a logical error in an existing invariant check
- Adding a new sovereignty flag with clear formal semantics

**Examples that are NOT TCB-eligible (regardless of how reasonable they sound):**
- "Add a regex to detect prompt injection in action descriptions"
- "Add a confidence threshold for when to bypass a flag"
- "Add a scheduler to decide action ordering"
- "Add a logging callback for debugging"
- "Add a config option to relax the ownerless machine check for testing"

---

## What we never accept (anywhere in the project)

- Changes that weaken the 10 sovereignty flags
- Removal or weakening of the A4, A6, or A7 checks
- "Emergency exception" paths that bypass the verifier
- NLP, ML inference, or semantic interpretation inside `engine.rs`
- Any change that makes `engine.rs` non-deterministic

These will be rejected regardless of stated motivation — including performance, emergencies, edge cases, or backwards compatibility.

---

## Process

1. Fork → branch → PR against `main`
2. Fill out the PR template — including the **TCB Gate section** if touching TCB files
3. All tests must pass: `pytest --cov=authgate --cov-fail-under=85`
4. Lint must pass: `ruff check src tests`
5. CI must pass: this includes the LOC guard and purity check on `engine.rs`

## Running locally

```bash
pip install -e ".[dev]"
pytest
```

If you are adding a new feature that lives in `extensions/`, add tests in `tests/`.
If you believe something belongs in the TCB, open an issue first — do not open a PR directly.

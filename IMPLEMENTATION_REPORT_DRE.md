# Implementation Report: Delegate Reputation Extension (DRE)

**Status:** Complete (Phases 1–5)  
**Target:** `authgate-kernel/src/authgate/extensions/`  
**Security Claim:** DRE is outside the TCB. It is an **optional behavioral risk overlay**. It returns advisory scores, not permit/deny verdicts. It cannot mint `Permit` and it cannot override `Deny`.

---

## Executive Summary

This PR implements the **Delegate Reputation Extension (DRE)**, an optional heuristic overlay that provides behavioral risk scoring for delegates. It scores a delegate's history, non-determinism class (NDC), and external attestation — but **the integrator decides what to do with the score**. The kernel TCB remains the sole authority gate.

**Key results:**
- **1,400 tests passing** (full suite green)
- **p99 latency: 2.8ms** on 10k-entry history (target: <5ms)
- **Zero changes** to `engine.rs`, `dag.rs`, `types.rs`, `call_gate.rs`, or any kernel file

---

## Phase Breakdown

### Phase 1: Core Scaffolding

**Files:**
- `src/authgate/extensions/delegate_reputation.py` — `DelegateReputationEngine`, `NDC` enum, `ReputationScore`, `ReputationAssessment`
- `src/authgate/extensions/historical_behavior_store.py` — SQLite-backed append-only `HistoricalBehaviorStore`
- `src/authgate/extensions/delegate_reputation_config.py` — Pydantic config model

**What it does:**
- Defines 7 NDC classes (`HUMAN` → `SWARM`) with configurable risk weights
- Implements the Delegation Chain Risk Score (DCRS) formula with chain-depth attenuation (`0.5^depth`)
- Append-only SQLite HBS with thread-safe connection-per-thread pattern
- **Advisory-only API:** `evaluate()` returns `(dcrs, requires_human_arbitration, risk_flags)` — never `Permit`/`Deny`

### Phase 2: Scoring Algorithm

**What it does:**
- Computes behavioral penalties: flagged actions (+0.3), denials (+0.1), resource breadth explosion (+0.2), failed attestations (+0.4)
- Applies exponential time-decay (`0.95^days`)
- Integrates external attestation penalty into DCRS

**Invariants enforced:**
1. **TCB Supremacy:** If kernel returns `Deny`, DRE returns empty assessment
2. **Monotonicity:** Adding a penalty never decreases DCRS
3. **Human Safety:** `HUMAN` with no violations always has low DCRS (< 0.5)
4. **Advisory-only:** DRE never returns a verdict; integrator decides

### Phase 3: Integration

**Files modified:**
- `src/authgate/extensions/__init__.py` — DRE **removed** from `ExtendedFreedomVerifier`; exposed as standalone module only
- `src/authgate/cli.py` — `--enable-dre` and `--dre-config` flags; DRE runs as post-verify advisory overlay
- `examples/langchain_integration/demo_with_dre.py` — End-to-end demo using standalone DRE pattern

**Design principle:** DRE is never on the default verify path. An integrator must explicitly call it after `FreedomVerifier.verify()`.

### Phase 4: External Attestation

**Files:**
- `src/authgate/extensions/attestation.py` — Pluggable attestor interface

**Production paths implemented:**
| Provider | Mechanism | Trust Score |
|----------|-----------|-------------|
| **SPIFFE/SVID** | `spiffe.WorkloadApiClient.fetch_svid()` | 0.85 base; 0.95 for production trust domain |
| **AWS IAM** | STS `GetCallerIdentity` + IAM role trust policy | 0.75 base; 0.85 for Service principal; 0.40 for wildcard principal |
| **GCP IAM** | Metadata server + `google.auth.default()` fallback | 0.80 custom SA; 0.50 default compute SA; 0.85 SDK fallback |
| **Azure IAM** | IMDS + MSI token + `DefaultAzureCredential` fallback | 0.85 with MSI; 0.60 without MSI; 0.80 SDK fallback |

**Lazy imports** — all cloud SDKs are optional; the module loads without them.

**Documentation:** `docs/attestation.md` — full interface guide with custom attestor examples.

### Phase 5: Hardening & Review

#### 5a. HBS Write Protection
**File:** `src/authgate/extensions/hbs_protection.py`

| Guard | Threshold | Behavior |
|-------|-----------|----------|
| Rate limit | Configurable per window | Blocks excessive writes per actor |
| Burst detection | Configurable per window | Flags rapid-fire write patterns |
| NDC spoofing detection | Config mismatches per window | Blocks actors that flip NDC too often |
| Resource breadth limit | Daily unique resource count | Blocks scan/probe behavior |

#### 5b. Performance Optimization

**Optimizations applied:**
1. Reduced 4 SQLite queries → 1 per evaluation by computing subset metrics in Python
2. Added `query_summary()` to HBS — aggregated counts entirely in SQL, zero row materialization
3. Added **covering index** `idx_actor_ts_covering` — `query_summary()` answered without table lookups
4. Added **partial indexes** for flagged records and failed attestations

**Benchmark results (10k-entry history, 1,000 evaluations):**
```
Mean:   2.527 ms
p50:    2.494 ms
p99:    2.868 ms   ✅ < 5.0 ms target
p99.9:  4.706 ms
```

#### 5c. Adversarial / Red-Team Tests
**File:** `tests/test_dre_adversarial.py` — 10 tests

| Test | Attack Vector | Defense Verified |
|------|--------------|------------------|
| History poisoning | 1,000 benign old records diluting 1 recent flag | Time-decay preserves recent penalty |
| NDC spoofing | Declare `DETERMINISTIC`, behave like LLM | Behavioral flags override spoofed NDC |
| Threshold probing | Vary patterns to find exact DCRS threshold | Borderline cases trigger arbitration flag |
| Burst attack | Rapid-fire HBS writes | Blocked by burst threshold |
| Resource breadth explosion | Scan >50 unique resources | Breadth penalty accumulates |
| Failed attestation flooding | Repeated invalid attestations | 0.4 penalty per failure |
| TCB supremacy | Perfect history + TCB Deny | DRE is silent; does not compute score |

#### 5d. Polarity Tests (Constitutional Boundary)
**File:** `tests/test_dre_polarity.py` — 4 tests

Ali demanded these four architectural invariants:

| Test | Invariant |
|------|-----------|
| `test_kernel_deny_plus_perfect_dcrs_still_deny` | Kernel Deny + excellent DCRS ⇒ still Deny |
| `test_dre_cannot_mint_permit` | DRE cannot mint Permit without a capability grant |
| `test_dre_is_not_shortcut_around_verify` | DRE requires a `VerificationResult` as input |
| `test_score_alone_is_insufficient_for_effect` | A score alone is never sufficient for an effect |

---

## Files Changed / Created

### New files
```
src/authgate/extensions/delegate_reputation.py
src/authgate/extensions/delegate_reputation_config.py
src/authgate/extensions/historical_behavior_store.py
src/authgate/extensions/hbs_protection.py
src/authgate/extensions/attestation.py
docs/attestation.md
benchmarks/dre_benchmark.py
examples/langchain_integration/demo_with_dre.py
tests/test_delegate_reputation.py
tests/test_delegate_reputation_config.py
tests/test_delegate_reputation_properties.py
tests/test_hbs_protection.py
tests/test_attestation_production.py
tests/test_dre_adversarial.py
tests/test_dre_polarity.py
```

### Modified files
```
src/authgate/extensions/__init__.py  (DRE removed from ExtendedFreedomVerifier)
src/authgate/cli.py                  (standalone DRE advisory mode)
```

### Reverted files
```
src/authgate/kernel/audit.py  (record_extension removed; zero kernel changes)
```

---

## Test Results

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

**Outcome:** `1400 passed, 1 skipped, 0 failed`

Key test modules:
- `test_delegate_reputation.py` — NDC matrix, historical penalties, TCB supremacy
- `test_attestation_production.py` — 26 tests (SPIFFE, AWS, GCP, Azure with mocked backends)
- `test_hbs_protection.py` — 10 tests (rate limiting, burst detection, NDC spoofing)
- `test_dre_adversarial.py` — 10 tests (poisoning, threshold probing, breadth explosion)
- `test_dre_polarity.py` — 4 tests (constitutional boundary invariants)

---

## Review Checklist

- [x] No changes to `authgate-kernel/src/tcb/` (verified by diff)
- [x] No changes to `src/authgate/kernel/` (verified by diff)
- [x] All lazy imports have graceful `ImportError` fallback
- [x] `NullAttestor` is neutral (valid=True, trust_score=1.0, penalty=0.0)
- [x] Failed real attestation returns penalty=0.5
- [x] DRE is advisory-only — returns scores, not verdicts
- [x] Benchmark p99 < 5ms on 10k-entry history
- [x] Full test suite green

---

## Next Steps (Optional)

1. **Production deployment:** Configure `GuardedBehaviorStore` with environment-specific rate limits
2. **Metrics export:** Wire DRE assessment counts into `/metrics` endpoint
3. **Human-in-the-loop:** UI for reviewing `requires_human_arbitration=True` cases
4. **PostgreSQL backend:** Extend `HistoricalBehaviorStore` for distributed deployments

---

*Implementation based on IMPLEMENTATION_BRIEF_DRE.md v1.0*  
*Reworked per review feedback: advisory-only, no kernel changes, explicit opt-in*

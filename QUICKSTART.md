# Quick Start — AuthGate Kernel

Get from zero to 1,401 green tests in under 5 minutes.

---

## 1. Install

```bash
git clone https://github.com/Aliipou/authgate-kernel.git
cd authgate-kernel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

> **System requirements:** Python 3.10+ (3.12 recommended). No Rust compiler needed for the Python test suite.

---

## 2. Verify the suite

```bash
pytest tests/ -q
```

You should see:

```
1400 passed, 1 skipped, 0 failed in ~3s
```

---

## 3. Run a single concept

| Want to see... | Run |
|----------------|-----|
| Core axioms (`says`, `controls`) | `pytest tests/test_core.py -v` |
| Delegation & attenuation | `pytest tests/test_delegate.py tests/test_delegation_abuse.py -v` |
| The "reasonable delegate" (DRE) | `pytest tests/test_dre_adversarial.py -v` |
| Policy language | `pytest tests/test_policy_dsl.py -v` |
| Audit & accountability | `pytest tests/test_audit.py tests/test_signed_audit.py -v` |
| Wire hardening | `pytest tests/test_wire_hardening.py -v` |
| Workload identity | `pytest tests/test_attestation_production.py -v` |

---

## 4. Run with DRE enabled

```python
from authgate import FreedomVerifier, OwnershipRegistry
from authgate.extensions.delegate_reputation import DelegateReputationEngine
from authgate.extensions.historical_behavior_store import HistoricalBehaviorStore

registry = OwnershipRegistry()
# ... register machines, add claims ...

hbs = HistoricalBehaviorStore(":memory:")  # or "/path/to/audit.db"
dre = DelegateReputationEngine(hbs=hbs)
verifier = FreedomVerifier(registry)

action = Action(action_id="read", actor=bot, resources_read=[dataset])
kernel_result = verifier.verify(action)
final_result = dre.evaluate(action, kernel_result, ndc=NDC.LLM_CLOSED)

print(final_result.permitted)   # True or False
print(final_result.reputation.dcrs)  # 0.0–2.0+ risk score
```

---

## 5. Run the benchmark

```bash
python benchmarks/dre_benchmark.py
```

Target: **< 5 ms p99** on 10k-entry history. Typical result: **~2.8 ms**.

---

## 6. File map

| File | What to read |
|------|-------------|
| `TEST_WALKTHROUGH_ABADI_LAMPSON.md` | Full test-by-test walkthrough with paper references |
| `PR_DESCRIPTION_DRE.md` | PR description for the DRE feature |
| `IMPLEMENTATION_REPORT_DRE.md` | Architectural rationale and threat model |
| `SEMANTICS.md` | Formal theorems T1–T4 (delegation lattice proofs) |
| `THREAT_MODEL.md` | 5 adversary classes, 7 attack scenarios |
| `docs/attestation.md` | Production attestation operator guide |

---

## 7. One-liners

```bash
# Run only DRE tests
pytest tests/test_dre_adversarial.py tests/test_hbs_protection.py -v

# Run with coverage
pytest tests/ --cov=src/authgate --cov-report=term-missing

# Run the LangChain + DRE demo
python examples/langchain_integration/demo_with_dre.py

# Run a specific adversarial scenario
pytest tests/test_dre_adversarial.py::test_history_poisoning_dilution_is_limited_by_decay -v

# Run formal property tests (Hypothesis)
pytest tests/test_proptest.py -v
```

---

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
`ModuleNotFoundError: No pytest` | `pip install pytest pytest-cov hypothesis` |
`1 failed, 1399 passed` | Check `tests/test_proptest.py` — may need `hypothesis` upgrade |
`Rust tests not found` | Expected — Python suite does not require Rust |
`Slow tests` | Add `-x` to stop on first failure, or `-k "not proptest"` to skip Hypothesis |

---

*Last updated: 2026-08-22. Test count: 1,400 passed, 1 skipped.*

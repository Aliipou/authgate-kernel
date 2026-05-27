# Plugin / Extension Model

**Phase:** 8 (Ecosystem Strategy)
**Status:** Initial draft — formalizing the existing extension architecture.

---

## Architecture

Extensions wrap the kernel. The kernel gate runs first, unconditionally.
Extensions cannot de-escalate a BLOCKED result, but can escalate a PERMITTED result to BLOCKED.

```
Action → engine.rs::verify() → PERMITTED → ExtensionChain → EnrichedResult
                             → BLOCKED   → (extensions do not run)
```

---

## Extension Interface

```python
from authgate.kernel.verifier import VerificationResult, Action
from typing import Protocol

class FreedomExtension(Protocol):
    name: str

    def check(
        self,
        action: Action,
        base_result: VerificationResult,
    ) -> VerificationResult:
        """
        Receive the PERMITTED base result. Return either:
        - base_result unchanged (pass-through)
        - A new VerificationResult with permitted=False (escalate to blocked)
        - A new VerificationResult with additional warnings (enrich)

        MUST NOT change permitted from False to True.
        MUST NOT modify base_result.signature.
        """
        ...
```

---

## Built-in Extensions

| Extension | Location | Description |
|---|---|---|
| `NonInterferenceChecker` | `extensions/ifc.py` | Bell-LaPadula IFC label checking |
| `ManipulationDetector` | `extensions/detection.py` | Heuristic manipulation score (signal only) |
| `PolicyVerifier` | `extensions/compass.py` | ABAC-style policy rules |
| `ConflictQueue` | `extensions/resolver.py` | Contested resource tracking |

---

## Registering a Custom Extension

```python
from authgate.kernel.verifier import FreedomVerifier

class MyExtension:
    name = "my-extension"

    def check(self, action, base_result):
        if "dangerous" in action.description:
            return VerificationResult(
                action_id=base_result.action_id,
                permitted=False,
                violations=base_result.violations + ("Custom: dangerous description",),
                warnings=base_result.warnings,
                confidence=base_result.confidence,
                requires_human_arbitration=True,
                manipulation_score=base_result.manipulation_score,
            )
        return base_result

verifier = FreedomVerifier(registry)
verifier.register_extension(MyExtension())
```

---

## Extension Isolation Requirements

1. Extensions MUST NOT modify the kernel's `signature` field
2. Extensions MUST NOT call `verify()` recursively
3. Extensions are UNTRUSTED — bugs here cannot cause false PERMITTED from the TCB
4. Extensions that raise exceptions are caught and logged; they do not crash the verifier
5. Extension source code is NOT audited as part of the TCB

---

## Standardized Capability Schemas

A shared schema registry allows extensions to interoperate:

```json
{
  "schema": "freedom-capability/v1",
  "kind": "WRITE",
  "resource_type": "database_table",
  "ifc_label": "SECRET",
  "risk": "Medium"
}
```

Schema registry: `freedom-specs/capability-schemas/` (planned).

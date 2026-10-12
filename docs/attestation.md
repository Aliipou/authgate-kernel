# External Attestation Interface

The `authgate.extensions.attestation` module provides pluggable **attestors** that verify a principal's identity and trustworthiness via external systems (SPIFFE, cloud IAM, etc.). Attestors feed into the **Delegate Reputation Extension (DRE)** as an additional signal that can only reduce trust — they can never override a kernel `Permit` into a `Deny`.

> **Security Note:** Attestors are **outside the TCB**. A failed attestation causes a reputation penalty, not a TCB block. The security claim remains on the kernel.

## Quick Start

```python
from authgate.extensions.attestation import CloudIAMAttestor, NullAttestor, CompositeAttestor

# Use a real cloud IAM attestor in production
aws = CloudIAMAttestor(provider="aws", stub_mode=False)
result = aws.attest("lambda-function-001")

# Or use a composite that tries multiple sources
composite = CompositeAttestor([
    CloudIAMAttestor(provider="aws", stub_mode=False),
    CloudIAMAttestor(provider="gcp", stub_mode=False),
    NullAttestor(),  # neutral fallback
])
```

## Attestor Base Class

All attestors inherit from `Attestor` and implement:

```python
class Attestor(ABC):
    @abstractmethod
    def attest(self, actor_id: str) -> AttestationResult: ...
```

### AttestationResult

```python
@dataclass(frozen=True)
class AttestationResult:
    valid: bool
    trust_score: float   # 0.0–1.0
    source: str          # e.g. "spiffe", "aws_iam"
    details: str = ""
```

The `penalty()` method computes the reputation impact:

- `valid=True, trust_score=1.0` → `penalty() == 0.0` (no impact)
- `valid=True, trust_score=0.2` → `penalty() == 0.8` (significant penalty)
- `valid=False` → `penalty() == 0.5` (moderate penalty regardless of trust_score)

## Built-in Attestors

### NullAttestor

Neutral attestor — always returns `valid=True, trust_score=1.0`. Use this when no external attestation is configured. It applies zero penalty.

### SpiffeAttestor

Verifies SPIFFE/SVID workload identity. Requires a running SPIFFE agent (e.g. SPIRE) and the `spiffe` Python package.

| Mode | Behavior |
|------|----------|
| `stub_mode=True` | Simulates attestation based on actor name |
| `stub_mode=False` | Calls `spiffe.WorkloadApiClient.fetch_svid()` |

Trust scoring heuristics:
- Base trust: **0.85**
- Production trust domain (contains "production"): **0.95**

### CloudIAMAttestor

Verifies cloud workload identity for AWS, GCP, or Azure.

| Provider | Production Path | Trust Score |
|----------|----------------|-------------|
| **AWS** | STS `GetCallerIdentity` + IAM role trust policy | 0.75 base; 0.85 if `Service` principal; 0.40 if wildcard `AWS` principal |
| **GCP** | Metadata server (`/computeMetadata/v1/...`) | 0.80 custom SA; 0.50 default compute SA; 0.85 SDK fallback |
| **Azure** | IMDS (`169.254.169.254`) + MSI token | 0.85 with MSI; 0.60 without MSI; 0.80 SDK fallback |

All cloud paths use a **2-second timeout** on metadata requests and gracefully degrade to SDK fallbacks.

### CompositeAttestor

Tries multiple attestors in sequence and returns the result with the **lowest penalty** (highest effective trust). If all fail, returns an invalid composite result.

## Writing a Custom Attestor

```python
from authgate.extensions.attestation import Attestor, AttestationResult

class MyCustomAttestor(Attestor):
    def attest(self, actor_id: str) -> AttestationResult:
        # Your attestation logic here
        return AttestationResult(
            valid=True,
            trust_score=0.9,
            source="my_custom",
            details="Attestation succeeded",
        )
```

Plug it into DRE via the `attestors` list in `DelegateReputationEngine`:

```python
from authgate.extensions.delegate_reputation import DelegateReputationEngine
from authgate.extensions.historical_behavior_store import HistoricalBehaviorStore

engine = DelegateReputationEngine(
    hbs=HistoricalBehaviorStore(":memory:"),
    attestors=[MyCustomAttestor()],
)
```

## Production Dependencies

| Provider | Package | Install |
|----------|---------|---------|
| SPIFFE | `spiffe` | `pip install spiffe` |
| AWS | `boto3` | `pip install boto3` |
| GCP | `google-auth` | `pip install google-auth` |
| Azure | `azure-identity` | `pip install azure-identity` |

All dependencies are **lazy-imported** — the module loads without them and only fails at runtime when a production attestor is instantiated without the required package.

## Configuration via DRE Config

You can configure attestors declaratively via `DelegateReputationConfig`:

```yaml
dre:
  threshold: 1.0
  attestors:
    - type: spiffe
      stub_mode: false
      socket_path: /tmp/spire-agent.sock
    - type: cloud_iam
      provider: aws
      stub_mode: false
```

See `delegate_reputation_config.py` for the full Pydantic schema.

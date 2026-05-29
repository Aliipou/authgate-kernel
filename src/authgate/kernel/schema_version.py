"""
Schema version tracking for capability semantics — II-3.

Every audit entry, VerificationResult, and issued capability is tagged with
the schema version under which it was produced. This enables:
  - Proof replay validation (reject proofs from incompatible versions)
  - Semantic drift detection (if semantics change, bump MAJOR)
  - Audit log interpretation (old logs remain interpretable)

See research/proof-versioning.md for the full versioning protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering


@dataclass(frozen=True)
@total_ordering
class SchemaVersion:
    """Semantic version for capability proof schemas."""
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, s: str) -> "SchemaVersion":
        parts = s.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid schema version: {s!r} (expected MAJOR.MINOR.PATCH)")
        try:
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            raise ValueError(f"Invalid schema version: {s!r} (non-integer component)")
        if major < 0 or minor < 0 or patch < 0:
            raise ValueError(f"Invalid schema version: {s!r} (negative component)")
        return cls(major, minor, patch)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def __lt__(self, other: "SchemaVersion") -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def is_compatible_with(self, other: "SchemaVersion") -> bool:
        """Two versions are compatible if they share the same MAJOR version."""
        return self.major == other.major

    def requires_reissuance(self, other: "SchemaVersion") -> bool:
        """True if proofs issued under `other` are incompatible with this version."""
        return not self.is_compatible_with(other)


# ── Current kernel schema version ──────────────────────────────────────────────

CURRENT_SCHEMA_VERSION = SchemaVersion(1, 0, 0)

# The rights bitmask semantics at this version — any change here requires a MAJOR bump
RIGHTS_SEMANTICS_V1 = {
    "RIGHT_READ":          "Read a named resource (file, dataset, API response)",
    "RIGHT_WRITE":         "Write or mutate a named resource",
    "RIGHT_DELEGATE":      "Delegate owned rights to another agent (with attenuation)",
    "RIGHT_EXECUTE":       "Execute a WASM module (not subprocess — see proof-versioning.md)",
    "RIGHT_SPAWN":         "Spawn a child agent with attenuated rights",
    "RIGHT_NETWORK":       "Make outbound network connections (client only)",
    "RIGHT_MODEL_INVOKE":  "Call an AI model inference API",
    "RIGHT_POLICY_MODIFY": "Modify kernel policy (catastrophic — human authorization required)",
}


def check_version_compatibility(
    proof_version: SchemaVersion | str,
    required_version: SchemaVersion | None = None,
) -> tuple[bool, str]:
    """
    Check if a proof's schema version is compatible with the current kernel.

    Returns (compatible: bool, reason: str).
    """
    if isinstance(proof_version, str):
        try:
            proof_version = SchemaVersion.parse(proof_version)
        except ValueError as e:
            return False, f"Invalid schema version in proof: {e}"

    target = required_version or CURRENT_SCHEMA_VERSION

    if proof_version.major != target.major:
        return False, (
            f"proof schema version {proof_version} is incompatible with "
            f"kernel version {target} (MAJOR mismatch — semantic drift possible)"
        )

    return True, ""


def version_tag() -> str:
    """Return the current schema version as a string for audit/log tagging."""
    return str(CURRENT_SCHEMA_VERSION)

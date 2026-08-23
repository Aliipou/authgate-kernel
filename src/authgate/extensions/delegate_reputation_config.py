"""
Pydantic configuration schema for the Delegate Reputation Extension (DRE).

Allows DRE engines to be configured from JSON / YAML / environment variables
with full validation.

Example (JSON):
    {
        "threshold": 1.0,
        "window_days": 90,
        "ndc_weights": {
            "HUMAN": 0.0,
            "DETERMINISTIC": 0.1,
            "LLM_CLOSED": 0.6,
            "LLM_OPEN": 0.8,
            "SWARM": 0.9
        },
        "max_unique_resources_penalty": 50,
        "attestor": {
            "kind": "spiffe",
            "socket_path": "/tmp/spire-agent/public/api.sock"
        }
    }
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from authgate.extensions.attestation import (
    Attestor,
    CloudIAMAttestor,
    CompositeAttestor,
    NullAttestor,
    SpiffeAttestor,
)
from authgate.extensions.delegate_reputation import DEFAULT_NDC_RISK, NDC
from authgate.extensions.historical_behavior_store import HistoricalBehaviorStore


# ---------------------------------------------------------------------------
# Attestor configuration models
# ---------------------------------------------------------------------------

class NullAttestorConfig(BaseModel):
    kind: Literal["null"]


class SpiffeAttestorConfig(BaseModel):
    kind: Literal["spiffe"]
    socket_path: str | None = None
    stub_mode: bool = True


class CloudIAMAttestorConfig(BaseModel):
    kind: Literal["cloud_iam"]
    provider: Literal["aws", "gcp", "azure"] = "aws"
    stub_mode: bool = True


class CompositeAttestorConfig(BaseModel):
    kind: Literal["composite"]
    attestors: list[AttestorConfig] = Field(default_factory=list)


AttestorConfig = (
    NullAttestorConfig
    | SpiffeAttestorConfig
    | CloudIAMAttestorConfig
    | CompositeAttestorConfig
)


# Fix forward reference for CompositeAttestorConfig attestors list
CompositeAttestorConfig.model_rebuild()


# ---------------------------------------------------------------------------
# DRE engine configuration
# ---------------------------------------------------------------------------

class DREConfig(BaseModel):
    """Validated configuration for DelegateReputationEngine."""

    hbs_path: str = ":memory:"
    threshold: float = Field(default=1.0, ge=0.0, le=10.0)
    window_days: int = Field(default=90, ge=1, le=365)
    ndc_weights: dict[str, float] = Field(default_factory=dict)
    max_unique_resources_penalty: int = Field(default=50, ge=0)
    attestor: AttestorConfig = Field(default_factory=lambda: NullAttestorConfig(kind="null"))

    @model_validator(mode="after")
    def _validate_ndc_weights(self) -> DREConfig:
        """Ensure all provided NDC weight keys are valid enum names."""
        valid_names = {ndc.name for ndc in NDC}
        for key in self.ndc_weights:
            if key not in valid_names:
                raise ValueError(
                    f"Invalid NDC weight key: {key!r}. "
                    f"Valid keys: {sorted(valid_names)}"
                )
        return self

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    def build_ndc_weights(self) -> dict[NDC, float]:
        """Merge default NDC risk weights with user overrides."""
        weights: dict[NDC, float] = dict(DEFAULT_NDC_RISK)
        for key, value in self.ndc_weights.items():
            weights[NDC[key]] = value
        return weights

    def build_attestor(self) -> Attestor:
        """Instantiate an Attestor from configuration."""
        cfg = self.attestor
        if cfg.kind == "null":
            return NullAttestor()
        if cfg.kind == "spiffe":
            return SpiffeAttestor(
                socket_path=cfg.socket_path,
                stub_mode=cfg.stub_mode,
            )
        if cfg.kind == "cloud_iam":
            return CloudIAMAttestor(
                provider=cfg.provider,
                stub_mode=cfg.stub_mode,
            )
        if cfg.kind == "composite":
            # Recursively build child attestors
            child_configs = [
                DREConfig(attestor=c).build_attestor()
                for c in cfg.attestors
            ]
            return CompositeAttestor(attestors=child_configs)
        raise ValueError(f"Unknown attestor kind: {cfg.kind}")

    def build_engine(self) -> Any:  # imported at runtime to avoid circular import
        """Build a fully-configured DelegateReputationEngine."""
        from authgate.extensions.delegate_reputation import DelegateReputationEngine

        hbs = HistoricalBehaviorStore(db_path=self.hbs_path)
        return DelegateReputationEngine(
            hbs=hbs,
            threshold=self.threshold,
            window_days=self.window_days,
            ndc_weights=self.build_ndc_weights(),
            max_unique_resources_penalty=self.max_unique_resources_penalty,
            attestor=self.build_attestor(),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DREConfig:
        """Create DREConfig from a plain dictionary (e.g. loaded JSON)."""
        return cls.model_validate(data)

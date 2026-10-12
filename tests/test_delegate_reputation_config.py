"""
Tests for the DRE Pydantic configuration model.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from authgate.extensions.delegate_reputation import DEFAULT_NDC_RISK, NDC
from authgate.extensions.delegate_reputation_config import DREConfig


# ---------------------------------------------------------------------------
# Basic validation
# ---------------------------------------------------------------------------

def test_default_config() -> None:
    """Default config should validate and build a working engine."""
    cfg = DREConfig()
    assert cfg.threshold == 1.0
    assert cfg.window_days == 90
    assert cfg.max_unique_resources_penalty == 50
    assert cfg.attestor.kind == "null"

    engine = cfg.build_engine()
    assert engine.threshold == 1.0
    engine.close()


def test_custom_threshold() -> None:
    cfg = DREConfig(threshold=0.75)
    assert cfg.threshold == 0.75


def test_threshold_out_of_bounds() -> None:
    with pytest.raises(ValidationError):
        DREConfig(threshold=-0.1)
    with pytest.raises(ValidationError):
        DREConfig(threshold=15.0)


def test_window_days_bounds() -> None:
    with pytest.raises(ValidationError):
        DREConfig(window_days=0)
    with pytest.raises(ValidationError):
        DREConfig(window_days=500)


# ---------------------------------------------------------------------------
# NDC weights
# ---------------------------------------------------------------------------

def test_ndc_weight_override() -> None:
    cfg = DREConfig(ndc_weights={"HUMAN": 0.5})
    weights = cfg.build_ndc_weights()
    assert weights[NDC.HUMAN] == 0.5
    # Others should remain defaults
    assert weights[NDC.LLM_CLOSED] == DEFAULT_NDC_RISK[NDC.LLM_CLOSED]


def test_invalid_ndc_weight_key() -> None:
    with pytest.raises(ValidationError) as exc_info:
        DREConfig(ndc_weights={"NOT_REAL_NDC": 0.5})
    assert "Invalid NDC weight key" in str(exc_info.value)


def test_all_ndc_weights_valid() -> None:
    """All valid NDC names should be accepted."""
    for ndc in NDC:
        cfg = DREConfig(ndc_weights={ndc.name: 0.42})
        assert cfg.build_ndc_weights()[ndc] == 0.42


# ---------------------------------------------------------------------------
# Attestor configurations
# ---------------------------------------------------------------------------

def test_null_attestor_config() -> None:
    cfg = DREConfig.from_dict({"attestor": {"kind": "null"}})
    attestor = cfg.build_attestor()
    result = attestor.attest("any-actor")
    assert result.penalty() == 0.0


def test_spiffe_attestor_config() -> None:
    cfg = DREConfig.from_dict({
        "attestor": {
            "kind": "spiffe",
            "socket_path": "/tmp/spire.sock",
            "stub_mode": True,
        }
    })
    attestor = cfg.build_attestor()
    result = attestor.attest("trusted-workload")
    assert result.valid
    assert result.source == "spiffe"


def test_cloud_iam_attestor_config() -> None:
    cfg = DREConfig.from_dict({
        "attestor": {
            "kind": "cloud_iam",
            "provider": "gcp",
            "stub_mode": True,
        }
    })
    attestor = cfg.build_attestor()
    result = attestor.attest("admin-user")
    assert result.valid
    assert result.source == "gcp_iam"


def test_composite_attestor_config() -> None:
    cfg = DREConfig.from_dict({
        "attestor": {
            "kind": "composite",
            "attestors": [
                {"kind": "null"},
                {"kind": "spiffe", "stub_mode": True},
            ]
        }
    })
    attestor = cfg.build_attestor()
    result = attestor.attest("any-actor")
    # Composite should pick the best (lowest penalty) result
    assert result.penalty() >= 0.0


# ---------------------------------------------------------------------------
# Integration: full engine from dict
# ---------------------------------------------------------------------------

def test_full_config_roundtrip() -> None:
    raw = {
        "hbs_path": ":memory:",
        "threshold": 0.85,
        "window_days": 30,
        "ndc_weights": {
            "LLM_OPEN": 0.9,
            "SWARM": 1.0,
        },
        "max_unique_resources_penalty": 25,
        "attestor": {"kind": "cloud_iam", "provider": "aws", "stub_mode": True},
    }
    cfg = DREConfig.from_dict(raw)
    engine = cfg.build_engine()

    assert engine.threshold == 0.85
    assert engine.window_days == 30
    assert engine.max_unique_resources_penalty == 25
    assert engine.ndc_weights[NDC.LLM_OPEN] == 0.9
    assert engine.ndc_weights[NDC.SWARM] == 1.0
    engine.close()

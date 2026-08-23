"""
Production attestation path tests (mocked external services).

These tests verify that SpiffeAttestor and CloudIAMAttestor behave
correctly when their production code paths are exercised against
mocked cloud metadata / SDK endpoints.

SECURITY NOTE: No real cloud credentials or SPIFFE sockets are required.
"""
from __future__ import annotations

import json
import sys
import types
import unittest.mock as mock
from typing import Any

import pytest

from authgate.extensions.attestation import (
    AttestationResult,
    CloudIAMAttestor,
    CompositeAttestor,
    NullAttestor,
    SpiffeAttestor,
)


# ---------------------------------------------------------------------------
# Inject fake cloud/SPIFFE modules so mock.patch can resolve them
# ---------------------------------------------------------------------------

def _make_fake_module(name: str, **attrs: Any) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    return mod


# SPIFFE (top-level module — simple)
_fake_spiffe = _make_fake_module("spiffe", WorkloadApiClient=mock.Mock)
sys.modules.setdefault("spiffe", _fake_spiffe)

# boto3 (top-level module — simple)
_fake_boto3 = _make_fake_module("boto3", client=mock.Mock)
sys.modules.setdefault("boto3", _fake_boto3)

# google.auth (needs parent package google)
_fake_google = _make_fake_module("google")
_fake_google_auth = _make_fake_module("google.auth", default=mock.Mock)
_fake_google.auth = _fake_google_auth
sys.modules.setdefault("google", _fake_google)
sys.modules.setdefault("google.auth", _fake_google_auth)

# azure.identity (needs parent package azure)
_fake_azure = _make_fake_module("azure")
_fake_azure_identity = _make_fake_module("azure.identity", DefaultAzureCredential=mock.Mock)
_fake_azure.identity = _fake_azure_identity
sys.modules.setdefault("azure", _fake_azure)
sys.modules.setdefault("azure.identity", _fake_azure_identity)


# ---------------------------------------------------------------------------
# NullAttestor
# ---------------------------------------------------------------------------

def test_null_attestor_is_neutral() -> None:
    """NullAttestor must return valid=True, trust_score=1.0, penalty=0.0."""
    attestor = NullAttestor()
    result = attestor.attest("any-actor")
    assert result.valid is True
    assert result.trust_score == 1.0
    assert result.penalty() == 0.0
    assert result.source == "null"


# ---------------------------------------------------------------------------
# SPIFFE production path (mocked)
# ---------------------------------------------------------------------------

def test_spiffe_production_valid_svid() -> None:
    """SpiffeAttestor should return high trust when a valid SVID is fetched."""
    mock_svid = mock.Mock()
    mock_svid.spiffe_id = mock.Mock()
    mock_svid.spiffe_id.trust_domain = "production.example.com"
    mock_svid.spiffe_id.__str__ = mock.Mock(return_value="spiffe://production.example.com/workload")

    mock_client = mock.Mock()
    mock_client.fetch_svid.return_value = mock_svid

    with mock.patch("spiffe.WorkloadApiClient", return_value=mock_client):
        attestor = SpiffeAttestor(socket_path="/tmp/spire.sock", stub_mode=False)
        result = attestor.attest("workload-001")

    assert result.valid is True
    assert result.source == "spiffe"
    assert result.trust_score == pytest.approx(0.95, abs=0.01)
    assert "production.example.com" in result.details


def test_spiffe_production_non_prod_trust_domain() -> None:
    """Trust score should be 0.85 when trust domain does NOT contain 'production'."""
    mock_svid = mock.Mock()
    mock_svid.spiffe_id = mock.Mock()
    mock_svid.spiffe_id.trust_domain = "dev.example.com"
    mock_svid.spiffe_id.__str__ = mock.Mock(return_value="spiffe://dev.example.com/workload")

    mock_client = mock.Mock()
    mock_client.fetch_svid.return_value = mock_svid

    with mock.patch("spiffe.WorkloadApiClient", return_value=mock_client):
        attestor = SpiffeAttestor(stub_mode=False)
        result = attestor.attest("workload-002")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.85, abs=0.01)


def test_spiffe_production_fetch_failure() -> None:
    """Failed SVID fetch should return invalid with penalty 0.5."""
    mock_client = mock.Mock()
    mock_client.fetch_svid.side_effect = Exception("socket not found")

    with mock.patch("spiffe.WorkloadApiClient", return_value=mock_client):
        attestor = SpiffeAttestor(stub_mode=False)
        result = attestor.attest("workload-003")

    assert result.valid is False
    assert result.trust_score == 0.0
    assert result.penalty() == 0.5
    assert result.source == "spiffe"


def test_spiffe_stub_mode() -> None:
    """Stub mode should not touch spiffe package."""
    attestor = SpiffeAttestor(stub_mode=True)
    assert attestor.stub_mode is True
    result = attestor.attest("trusted-actor")
    assert result.valid is True
    assert result.trust_score == pytest.approx(0.95, abs=0.01)

    result2 = attestor.attest("anonymous-actor")
    assert result2.valid is False
    assert result2.penalty() == 0.5


# ---------------------------------------------------------------------------
# AWS production path (mocked boto3)
# ---------------------------------------------------------------------------

def test_aws_production_service_principal() -> None:
    """AWS role with Service principal should score >= 0.85."""
    mock_sts = mock.Mock()
    mock_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session",
        "Account": "123456789012",
    }

    mock_iam = mock.Mock()
    mock_iam.get_role.return_value = {
        "Role": {
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Effect": "Allow",
                    }
                ]
            }
        }
    }

    def _fake_boto3_client(service: str, **kwargs: Any) -> Any:
        if service == "sts":
            return mock_sts
        if service == "iam":
            return mock_iam
        raise ValueError(service)

    with mock.patch("boto3.client", side_effect=_fake_boto3_client):
        attestor = CloudIAMAttestor(provider="aws", stub_mode=False)
        result = attestor.attest("lambda-function")

    assert result.valid is True
    assert result.source == "aws_iam"
    assert result.trust_score >= 0.85


def test_aws_production_wildcard_principal_penalty() -> None:
    """AWS role with wildcard AWS principal should drop to 0.4."""
    mock_sts = mock.Mock()
    mock_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:sts::123456789012:assumed-role/RiskyRole/session",
        "Account": "123456789012",
    }

    mock_iam = mock.Mock()
    mock_iam.get_role.return_value = {
        "Role": {
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Principal": {"AWS": "*"},
                        "Effect": "Allow",
                    }
                ]
            }
        }
    }

    def _fake_boto3_client(service: str, **kwargs: Any) -> Any:
        if service == "sts":
            return mock_sts
        if service == "iam":
            return mock_iam
        raise ValueError(service)

    with mock.patch("boto3.client", side_effect=_fake_boto3_client):
        attestor = CloudIAMAttestor(provider="aws", stub_mode=False)
        result = attestor.attest("risky-role")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.4, abs=0.01)
    assert "wildcard" in result.details.lower() or "WARNING" in result.details


def test_aws_production_no_boto3() -> None:
    """If boto3 is not installed, attestation should be invalid."""
    attestor = CloudIAMAttestor(provider="aws", stub_mode=False)
    saved = sys.modules.pop("boto3", None)
    try:
        orig_import = __builtins__["__import__"]

        def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "boto3":
                raise ImportError("no boto3")
            return orig_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=_fake_import):
            result = attestor.attest("no-boto3")
    finally:
        if saved:
            sys.modules["boto3"] = saved

    assert result.valid is False
    assert result.penalty() == 0.5
    assert "boto3" in result.details.lower()


# ---------------------------------------------------------------------------
# GCP production path (mocked internal methods)
# ---------------------------------------------------------------------------

def test_gcp_production_metadata_server() -> None:
    """GCP metadata server returning a custom SA should score 0.8."""
    fake_email = "my-sa@my-project.iam.gserviceaccount.com"

    with mock.patch.object(
        CloudIAMAttestor, "_gcp_metadata_service_account", return_value=fake_email
    ):
        attestor = CloudIAMAttestor(provider="gcp", stub_mode=False)
        result = attestor.attest("gcp-workload")

    assert result.valid is True
    assert result.source == "gcp_iam"
    assert result.trust_score == pytest.approx(0.8, abs=0.01)
    assert fake_email in result.details


def test_gcp_production_default_compute_sa_penalty() -> None:
    """Default compute service account should drop trust score to 0.5."""
    fake_email = "123456789012-compute@developer.gserviceaccount.com"

    with mock.patch.object(
        CloudIAMAttestor, "_gcp_metadata_service_account", return_value=fake_email
    ):
        attestor = CloudIAMAttestor(provider="gcp", stub_mode=False)
        result = attestor.attest("gcp-default")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.5, abs=0.01)
    assert "default compute" in result.details.lower() or "WARNING" in result.details


def test_gcp_production_fallback_google_auth() -> None:
    """If metadata server fails, GCP should fall back to google.auth.default."""
    fake_email = "fallback-sa@project.iam.gserviceaccount.com"

    mock_creds = mock.Mock()
    mock_creds.service_account_email = fake_email

    with mock.patch.object(
        CloudIAMAttestor, "_gcp_metadata_service_account", side_effect=Exception("metadata unavailable")
    ):
        with mock.patch("google.auth.default", return_value=(mock_creds, "my-project")):
            attestor = CloudIAMAttestor(provider="gcp", stub_mode=False)
            result = attestor.attest("gcp-fallback")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.85, abs=0.01)
    assert fake_email in result.details


def test_gcp_production_complete_failure() -> None:
    """If both metadata server and google.auth fail, attestation is invalid."""
    with mock.patch.object(
        CloudIAMAttestor, "_gcp_metadata_service_account", side_effect=Exception("metadata unavailable")
    ):
        with mock.patch("google.auth.default", side_effect=Exception("no creds")):
            attestor = CloudIAMAttestor(provider="gcp", stub_mode=False)
            result = attestor.attest("gcp-fail")

    assert result.valid is False
    assert result.penalty() == 0.5
    assert "gcp" in result.details.lower()


# ---------------------------------------------------------------------------
# Azure production path (mocked internal methods)
# ---------------------------------------------------------------------------

class _FakeHttpResponse:
    """Minimal file-like object that supports the context-manager protocol."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: Any) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_azure_production_imds_with_msi() -> None:
    """Azure VM with MSI identity should score 0.85."""
    imds_body = {
        "vmId": "vm-123",
        "subscriptionId": "sub-456",
        "resourceGroupName": "rg-test",
    }
    msi_body = {"access_token": "fake-token", "token_type": "Bearer"}

    def _fake_urlopen(req: Any, **kwargs: Any) -> Any:
        url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
        if "instance/compute" in url:
            return _FakeHttpResponse(json.dumps(imds_body).encode("utf-8"))
        raise ValueError(f"Unexpected URL: {url}")

    with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        attestor = CloudIAMAttestor(provider="azure", stub_mode=False)
        # Patch MSI token on the instance to avoid static-method descriptor quirks
        attestor._azure_msi_token = lambda: msi_body  # type: ignore[method-assign]
        result = attestor.attest("azure-vm")

    assert result.valid is True
    assert result.source == "azure_iam"
    assert result.trust_score == pytest.approx(0.85, abs=0.01)
    assert "vm-123" in result.details
    assert "MSI" in result.details


def test_azure_production_imds_no_msi() -> None:
    """Azure VM without MSI should score 0.6."""
    imds_body = {
        "vmId": "vm-789",
        "subscriptionId": "sub-000",
        "resourceGroupName": "rg-prod",
    }

    def _fake_urlopen(req: Any, **kwargs: Any) -> Any:
        url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
        if "instance/compute" in url:
            return _FakeHttpResponse(json.dumps(imds_body).encode("utf-8"))
        raise ValueError(f"Unexpected URL: {url}")

    with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        attestor = CloudIAMAttestor(provider="azure", stub_mode=False)
        attestor._azure_msi_token = lambda: None  # type: ignore[method-assign]
        result = attestor.attest("azure-no-msi")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.6, abs=0.01)
    assert "no MSI" in result.details


def test_azure_production_sdk_fallback() -> None:
    """If IMDS fails entirely, Azure should fall back to DefaultAzureCredential."""
    mock_token = mock.Mock()
    mock_token.token = "sdk-token"

    mock_cred = mock.Mock()
    mock_cred.get_token.return_value = mock_token

    with mock.patch("urllib.request.urlopen", side_effect=Exception("IMDS unreachable")):
        with mock.patch("azure.identity.DefaultAzureCredential", return_value=mock_cred):
            attestor = CloudIAMAttestor(provider="azure", stub_mode=False)
            result = attestor.attest("azure-sdk")

    assert result.valid is True
    assert result.trust_score == pytest.approx(0.8, abs=0.01)
    assert "SDK" in result.details


def test_azure_production_complete_failure() -> None:
    """If both IMDS and SDK fail, attestation is invalid."""
    with mock.patch("urllib.request.urlopen", side_effect=Exception("IMDS unreachable")):
        with mock.patch("azure.identity.DefaultAzureCredential", side_effect=Exception("no azure-identity")):
            attestor = CloudIAMAttestor(provider="azure", stub_mode=False)
            result = attestor.attest("azure-fail")

    assert result.valid is False
    assert result.penalty() == 0.5
    assert "azure" in result.details.lower()


# ---------------------------------------------------------------------------
# CompositeAttestor
# ---------------------------------------------------------------------------

def test_composite_returns_best_result() -> None:
    """CompositeAttestor should return the result with the lowest penalty."""
    a = mock.Mock(spec=CloudIAMAttestor)
    a.attest.return_value = AttestationResult(
        valid=False, trust_score=0.0, source="aws_iam", details="fail"
    )

    b = mock.Mock(spec=SpiffeAttestor)
    b.attest.return_value = AttestationResult(
        valid=True, trust_score=0.8, source="spiffe", details="ok"
    )

    composite = CompositeAttestor([a, b])
    result = composite.attest("actor")

    assert result.source == "spiffe"
    assert result.trust_score == pytest.approx(0.8, abs=0.01)
    assert result.penalty() == pytest.approx(0.2, abs=0.01)


def test_composite_all_fail() -> None:
    """If all attestors fail, composite returns invalid."""
    a = mock.Mock(spec=CloudIAMAttestor)
    a.attest.side_effect = Exception("boom")

    b = mock.Mock(spec=SpiffeAttestor)
    b.attest.side_effect = Exception("bang")

    composite = CompositeAttestor([a, b])
    result = composite.attest("actor")

    assert result.valid is False
    assert result.source == "composite"
    assert "all attestors failed" in result.details.lower()


# ---------------------------------------------------------------------------
# AttestationResult penalty edge cases
# ---------------------------------------------------------------------------

def test_penalty_for_valid_high_trust() -> None:
    """Valid with trust_score 1.0 → penalty 0.0."""
    r = AttestationResult(valid=True, trust_score=1.0, source="test")
    assert r.penalty() == 0.0


def test_penalty_for_valid_low_trust() -> None:
    """Valid with trust_score 0.2 → penalty 0.8."""
    r = AttestationResult(valid=True, trust_score=0.2, source="test")
    assert r.penalty() == pytest.approx(0.8, abs=0.01)


def test_penalty_for_invalid() -> None:
    """Invalid always returns penalty 0.5 regardless of trust_score."""
    r = AttestationResult(valid=False, trust_score=0.0, source="test")
    assert r.penalty() == 0.5

    r2 = AttestationResult(valid=False, trust_score=0.9, source="test")
    assert r2.penalty() == 0.5


# ---------------------------------------------------------------------------
# CloudIAM stub mode parameterized
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("provider,actor_id,expected_valid,expected_score", [
    ("aws", "admin-user", True, 0.9),
    ("aws", "service-bot", True, 0.8),
    ("aws", "random", False, 0.0),
    ("gcp", "admin-user", True, 0.9),
    ("azure", "service-bot", True, 0.8),
])
def test_cloud_iam_stub_mode_parametrized(
    provider: str,
    actor_id: str,
    expected_valid: bool,
    expected_score: float,
) -> None:
    """Stub mode should behave consistently across providers."""
    attestor = CloudIAMAttestor(provider=provider, stub_mode=True)
    result = attestor.attest(actor_id)
    assert result.valid == expected_valid
    assert result.trust_score == pytest.approx(expected_score, abs=0.01)

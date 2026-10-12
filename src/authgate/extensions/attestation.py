"""
External attestation interface for the Delegate Reputation Extension.

This module provides pluggable attestors that verify a principal's identity
and trustworthiness via external systems (SPIFFE, cloud IAM, etc.).

SECURITY NOTE: Attestors are outside the TCB. A failed attestation causes a
reputation penalty, not a TCB block. The security claim remains on the kernel.

Production dependencies (lazy-imported):
  - SPIFFE:  pip install spiffe
  - AWS:     pip install boto3
  - GCP:     requests (already in stdlib via urllib, but requests is easier)
  - Azure:   requests
"""
from __future__ import annotations

import json
import logging
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("authgate.extensions.attestation")


@dataclass(frozen=True)
class AttestationResult:
    """Result of an external attestation check."""
    valid: bool
    trust_score: float  # 0.0–1.0; 1.0 = fully trusted
    source: str         # e.g. "spiffe", "aws_iam", "gcp_iam"
    details: str = ""   # Human-readable detail

    def penalty(self) -> float:
        """Return reputation penalty (0.0 = no penalty, 1.0 = max opacity)."""
        if self.valid:
            return max(0.0, 1.0 - self.trust_score)
        return 0.5  # Invalid attestation = moderate penalty


class Attestor(ABC):
    """Abstract base for external identity/trust attestors."""

    @abstractmethod
    def attest(self, actor_id: str) -> AttestationResult:
        """Attest the given actor. Must be implemented by subclasses."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# SPIFFE / SVID attestor
# ---------------------------------------------------------------------------

class SpiffeAttestor(Attestor):
    """
    Attestor backed by SPIFFE/SVID workload identity.

    Production usage requires the `spiffe` Python package and a running
    SPIFFE agent (e.g. SPIRE) with a Unix-domain socket.

    Args:
        socket_path: Path to the SPIFFE Workload API socket.
                     If None, uses the default SPIFFE_ENDPOINT_SOCKET env var.
        stub_mode:   If True, simulates attestation for testing.
    """

    def __init__(self, socket_path: str | None = None, stub_mode: bool = True) -> None:
        self.socket_path = socket_path
        self.stub_mode = stub_mode
        if not stub_mode:
            try:
                import spiffe  # type: ignore[import-untyped]
                self._client = spiffe.WorkloadApiClient(socket_path=socket_path)
            except ImportError as e:
                raise RuntimeError(
                    "SpiffeAttestor in non-stub mode requires the 'spiffe' package. "
                    "Install with: pip install spiffe"
                ) from e

    def attest(self, actor_id: str) -> AttestationResult:
        if self.stub_mode:
            return self._stub_attest(actor_id)
        return self._production_attest(actor_id)

    def _stub_attest(self, actor_id: str) -> AttestationResult:
        if "trusted" in actor_id.lower():
            return AttestationResult(
                valid=True, trust_score=0.95, source="spiffe",
                details="Stub: trusted SVID",
            )
        return AttestationResult(
            valid=False, trust_score=0.0, source="spiffe",
            details="Stub: no SVID found",
        )

    def _production_attest(self, actor_id: str) -> AttestationResult:
        try:
            import spiffe
            svid = self._client.fetch_svid()  # type: ignore[union-attr]
            if svid and svid.spiffe_id:
                # Parse SPIFFE ID: spiffe://trust-domain/path
                spiffe_id = str(svid.spiffe_id)
                trust_domain = svid.spiffe_id.trust_domain

                # Trust scoring heuristics
                trust_score = 0.85
                details = f"SVID valid: {spiffe_id}"

                # Boost trust for known safe trust domains (configurable in real deploy)
                if trust_domain and "production" in str(trust_domain).lower():
                    trust_score = 0.95
                    details += " (production trust domain)"

                return AttestationResult(
                    valid=True, trust_score=trust_score, source="spiffe",
                    details=details,
                )
        except Exception as e:
            logger.warning("SPIFFE attestation failed: %s", e)

        return AttestationResult(
            valid=False, trust_score=0.0, source="spiffe",
            details="SVID fetch failed",
        )


# ---------------------------------------------------------------------------
# Cloud IAM attestor
# ---------------------------------------------------------------------------

class CloudIAMAttestor(Attestor):
    """
    Attestor backed by cloud IAM workload identity.

    Supports AWS, GCP, and Azure. In production, attempts to verify the
    workload's identity via cloud-native metadata services or SDK APIs.

    Args:
        provider:   "aws", "gcp", or "azure"
        stub_mode:  If True, simulates attestation for testing.
    """

    def __init__(self, provider: str = "aws", stub_mode: bool = True) -> None:
        if provider not in ("aws", "gcp", "azure"):
            raise ValueError(f"Unknown provider: {provider}")
        self.provider = provider
        self.stub_mode = stub_mode

    def attest(self, actor_id: str) -> AttestationResult:
        if self.stub_mode:
            return self._stub_attest(actor_id)
        return self._production_attest(actor_id)

    def _stub_attest(self, actor_id: str) -> AttestationResult:
        lower = actor_id.lower()
        if "admin" in lower:
            return AttestationResult(
                valid=True, trust_score=0.9, source=f"{self.provider}_iam",
                details="Stub: admin role detected",
            )
        if "service" in lower:
            return AttestationResult(
                valid=True, trust_score=0.8, source=f"{self.provider}_iam",
                details="Stub: service account detected",
            )
        return AttestationResult(
            valid=False, trust_score=0.0, source=f"{self.provider}_iam",
            details="Stub: no IAM match",
        )

    def _production_attest(self, actor_id: str) -> AttestationResult:
        if self.provider == "aws":
            return self._aws_attest(actor_id)
        if self.provider == "gcp":
            return self._gcp_attest(actor_id)
        if self.provider == "azure":
            return self._azure_attest(actor_id)
        return AttestationResult(
            valid=False, trust_score=0.0, source=f"{self.provider}_iam",
            details="Unknown provider",
        )

    # ------------------------------------------------------------------
    # AWS production path
    # ------------------------------------------------------------------

    def _aws_attest(self, actor_id: str) -> AttestationResult:
        """Verify AWS identity via STS GetCallerIdentity + IAM role trust."""
        try:
            import boto3  # type: ignore[import-untyped]
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            arn = identity.get("Arn", "")
            account = identity.get("Account", "")

            # Try to enrich with IAM role trust policy
            trust_score = 0.75
            details = f"AWS identity: {arn}"

            try:
                iam = boto3.client("iam")
                # Extract role name from ARN if this is a role assumption
                if ":assumed-role/" in arn:
                    role_name = arn.split("/")[-2]
                elif ":role/" in arn:
                    role_name = arn.split("/")[-1]
                else:
                    role_name = None

                if role_name:
                    role = iam.get_role(RoleName=role_name)
                    trust_policy = role.get("Role", {}).get("AssumeRolePolicyDocument", {})
                    # Score based on trust policy principals
                    statements = trust_policy.get("Statement", [])
                    for stmt in statements:
                        principals = stmt.get("Principal", {})
                        if "Service" in principals:
                            # Service-linked role is more trustworthy than broad assume
                            trust_score = max(trust_score, 0.85)
                        if "AWS" in principals:
                            val = principals["AWS"]
                            if isinstance(val, str) and val == "*":
                                # Wildcard principal is dangerous
                                trust_score = min(trust_score, 0.4)
                                details += " [WARNING: wildcard AssumeRolePrincipal]"
            except Exception as e:
                logger.debug("IAM role enrichment failed: %s", e)

            return AttestationResult(
                valid=True, trust_score=trust_score, source="aws_iam",
                details=details,
            )
        except ImportError:
            logger.warning("boto3 not installed; cannot perform AWS attestation")
            return AttestationResult(
                valid=False, trust_score=0.0, source="aws_iam",
                details="boto3 not installed",
            )
        except Exception as e:
            logger.warning("AWS attestation failed: %s", e)
            return AttestationResult(
                valid=False, trust_score=0.0, source="aws_iam",
                details=f"AWS attestation failed: {e}",
            )

    # ------------------------------------------------------------------
    # GCP production path
    # ------------------------------------------------------------------

    def _gcp_attest(self, actor_id: str) -> AttestationResult:
        """Verify GCP identity via metadata server or IAM API."""
        # 1. Try metadata server (works inside GCP without credentials)
        try:
            sa_email = self._gcp_metadata_service_account()
            if sa_email:
                trust_score = 0.8
                details = f"GCP service account: {sa_email}"
                # Lower trust for default compute service account
                if "compute@developer.gserviceaccount.com" in sa_email:
                    trust_score = 0.5
                    details += " [WARNING: default compute SA]"
                return AttestationResult(
                    valid=True, trust_score=trust_score, source="gcp_iam",
                    details=details,
                )
        except Exception as e:
            logger.debug("GCP metadata server attestation failed: %s", e)

        # 2a. Fallback: try google.auth directly
        try:
            from google.auth import default as google_auth_default
            credentials, project = google_auth_default()
            if credentials and credentials.service_account_email:
                return AttestationResult(
                    valid=True, trust_score=0.85, source="gcp_iam",
                    details=f"GCP authenticated SA: {credentials.service_account_email}",
                )
        except ImportError:
            logger.debug("google-auth not installed")
        except Exception as e:
            logger.debug("GCP auth fallback failed: %s", e)

        # 2b. Fallback: try google-cloud-iam if available
        try:
            from google.cloud import iam_credentials_v1  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("google-cloud-iam not installed")
        except Exception as e:
            logger.debug("GCP IAM API attestation failed: %s", e)

        return AttestationResult(
            valid=False, trust_score=0.0, source="gcp_iam",
            details="GCP attestation failed (not running in GCP?)",
        )

    @staticmethod
    def _gcp_metadata_service_account() -> str | None:
        """Query GCP metadata server for service account email."""
        req = urllib.request.Request(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.read().decode("utf-8").strip()

    # ------------------------------------------------------------------
    # Azure production path
    # ------------------------------------------------------------------

    def _azure_attest(self, actor_id: str) -> AttestationResult:
        """Verify Azure identity via Instance Metadata Service (IMDS)."""
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
                headers={"Metadata": "true"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vm_id = data.get("vmId", "")
                subscription_id = data.get("subscriptionId", "")
                resource_group = data.get("resourceGroupName", "")

                # Try MSI token endpoint for identity
                msi = self._azure_msi_token()
                if msi:
                    details = f"Azure VM {vm_id} with MSI identity"
                    trust_score = 0.85
                else:
                    details = f"Azure VM {vm_id} (no MSI identity)"
                    trust_score = 0.6

                return AttestationResult(
                    valid=True, trust_score=trust_score, source="azure_iam",
                    details=details,
                )
        except Exception as e:
            logger.debug("Azure IMDS attestation failed: %s", e)

        # Fallback: try azure-identity SDK
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
            cred = DefaultAzureCredential()
            token = cred.get_token("https://management.azure.com/.default")
            if token and token.token:
                return AttestationResult(
                    valid=True, trust_score=0.8, source="azure_iam",
                    details="Azure identity authenticated via SDK",
                )
        except ImportError:
            logger.debug("azure-identity not installed")
        except Exception as e:
            logger.debug("Azure SDK attestation failed: %s", e)

        return AttestationResult(
            valid=False, trust_score=0.0, source="azure_iam",
            details="Azure attestation failed (not running in Azure?)",
        )

    @staticmethod
    def _azure_msi_token() -> dict[str, Any] | None:
        """Query Azure MSI token endpoint for managed identity."""
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/",
                headers={"Metadata": "true"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Composite attestor (tries multiple sources, returns best result)
# ---------------------------------------------------------------------------

class CompositeAttestor(Attestor):
    """Tries multiple attestors and returns the result with the lowest penalty."""

    def __init__(self, attestors: list[Attestor]) -> None:
        self.attestors = attestors

    def attest(self, actor_id: str) -> AttestationResult:
        best: AttestationResult | None = None
        for attestor in self.attestors:
            try:
                result = attestor.attest(actor_id)
                if best is None or result.penalty() < best.penalty():
                    best = result
            except Exception as e:
                logger.warning("Attestor %s failed: %s", type(attestor).__name__, e)

        if best is None:
            return AttestationResult(
                valid=False, trust_score=0.0, source="composite",
                details="All attestors failed",
            )
        return best


# ---------------------------------------------------------------------------
# Null attestor (always returns neutral — no external attestation available)
# ---------------------------------------------------------------------------

class NullAttestor(Attestor):
    """Neutral attestor — no external attestation configured, no penalty applied."""

    def attest(self, actor_id: str) -> AttestationResult:
        return AttestationResult(
            valid=True, trust_score=1.0, source="null",
            details="No external attestation configured",
        )

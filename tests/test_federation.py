"""Tests for Phase 5: Distributed Constitutional Federation."""
import time

import pytest

from authgate.kernel.federation import (
    ConstitutionalConsensus,
    FederatedDecision,
    FederatedDecisionType,
    FederatedKernelID,
    FederationGateway,
)


def _kernel(kid: str, domain: str = "general", trust: int = 3) -> FederatedKernelID:
    return FederatedKernelID(kernel_id=kid, domain=domain, trust_level=trust)


def _permit(kernel: FederatedKernelID, action_id: str = "op") -> FederatedDecision:
    return FederatedDecision.from_result(kernel, action_id, permitted=True, violations=[])


def _deny(kernel: FederatedKernelID, reason: str = "blocked", action_id: str = "op") -> FederatedDecision:
    return FederatedDecision.from_result(kernel, action_id, permitted=False, violations=[reason])


class TestFederatedKernelID:
    def test_valid_kernel(self):
        k = _kernel("k1")
        assert k.kernel_id == "k1"

    def test_empty_id_raises(self):
        with pytest.raises(ValueError):
            FederatedKernelID(kernel_id="", domain="x", trust_level=3)

    def test_trust_level_out_of_range(self):
        with pytest.raises(ValueError):
            FederatedKernelID(kernel_id="k", domain="x", trust_level=6)

    def test_trust_level_zero_raises(self):
        with pytest.raises(ValueError):
            FederatedKernelID(kernel_id="k", domain="x", trust_level=0)


class TestFederatedDecision:
    def test_permit_from_result(self):
        k = _kernel("k1")
        d = FederatedDecision.from_result(k, "op", permitted=True, violations=[])
        assert d.is_permit()
        assert not d.is_deny()

    def test_deny_from_result(self):
        k = _kernel("k1")
        d = FederatedDecision.from_result(k, "op", permitted=False, violations=["no claim"])
        assert d.is_deny()

    def test_proof_commitment_is_64_hex(self):
        k = _kernel("k1")
        d = FederatedDecision.from_result(k, "op", permitted=True, violations=[])
        assert len(d.proof_commitment) == 64


class TestConstitutionalConsensus:
    def test_all_permit_passes(self):
        consensus = ConstitutionalConsensus(threshold=0.66)
        k1, k2, k3 = _kernel("k1"), _kernel("k2"), _kernel("k3")
        result = consensus.evaluate([_permit(k1), _permit(k2), _permit(k3)])
        assert result.permitted
        assert result.permit_count == 3

    def test_majority_deny_blocks(self):
        consensus = ConstitutionalConsensus(threshold=0.66)
        k1, k2, k3 = _kernel("k1"), _kernel("k2"), _kernel("k3")
        result = consensus.evaluate([_deny(k1), _deny(k2), _permit(k3)])
        assert not result.permitted

    def test_supermajority_permit_passes(self):
        consensus = ConstitutionalConsensus(threshold=0.66)
        kernels = [_kernel(f"k{i}") for i in range(5)]
        decisions = [_permit(k) for k in kernels[:4]] + [_deny(kernels[4])]
        result = consensus.evaluate(decisions)
        assert result.permitted  # 4/5 = 80% >= 66%

    def test_veto_by_high_trust_kernel(self):
        consensus = ConstitutionalConsensus(threshold=0.51)
        high_trust = _kernel("veto-k", trust=4)
        low1, low2 = _kernel("k1", trust=2), _kernel("k2", trust=2)
        # Even if 2/3 permit, the veto kernel denies
        result = consensus.evaluate([_deny(high_trust), _permit(low1), _permit(low2)])
        assert not result.permitted
        assert "veto-k" in result.denying_kernels

    def test_no_decisions_denied(self):
        consensus = ConstitutionalConsensus()
        result = consensus.evaluate([])
        assert not result.permitted

    def test_all_abstain_denied(self):
        consensus = ConstitutionalConsensus()
        k = _kernel("k1")
        abstain = FederatedDecision(
            kernel_id=k, action_id="op",
            decision=FederatedDecisionType.ABSTAIN,
            proof_commitment="0" * 64,
            timestamp=time.time(),
        )
        result = consensus.evaluate([abstain])
        assert not result.permitted

    def test_threshold_validation(self):
        with pytest.raises(ValueError):
            ConstitutionalConsensus(threshold=0.4)  # ≤ 0.5
        with pytest.raises(ValueError):
            ConstitutionalConsensus(threshold=1.1)

    def test_achieved_fraction_correct(self):
        consensus = ConstitutionalConsensus(threshold=0.66)
        k1, k2 = _kernel("k1"), _kernel("k2")
        result = consensus.evaluate([_permit(k1), _deny(k2)])
        assert abs(result.achieved_fraction - 0.5) < 0.01


class TestFederationGateway:
    def test_register_and_list_kernels(self):
        gw = FederationGateway()
        k = _kernel("k1")
        gw.register_kernel(k)
        assert k in gw.registered_kernels()

    def test_duplicate_register_raises(self):
        gw = FederationGateway()
        k = _kernel("k1")
        gw.register_kernel(k)
        with pytest.raises(ValueError):
            gw.register_kernel(k)

    def test_unregistered_decision_invalid(self):
        gw = FederationGateway()
        k = _kernel("unknown-k")
        d = _permit(k)
        assert not gw.validate_decision(d)

    def test_registered_decision_valid(self):
        gw = FederationGateway()
        k = _kernel("k1")
        gw.register_kernel(k)
        d = _permit(k)
        assert gw.validate_decision(d)

    def test_stale_decision_invalid(self):
        gw = FederationGateway()
        k = _kernel("k1")
        gw.register_kernel(k)
        stale = FederatedDecision(
            kernel_id=k, action_id="op",
            decision=FederatedDecisionType.PERMIT,
            proof_commitment="a" * 64,
            timestamp=time.time() - 400,  # >300s old
        )
        assert not gw.validate_decision(stale)

    def test_gateway_evaluate_all_permit(self):
        gw = FederationGateway()
        k1, k2 = _kernel("k1"), _kernel("k2")
        gw.register_kernel(k1)
        gw.register_kernel(k2)
        result = gw.evaluate([_permit(k1), _permit(k2)])
        assert result.permitted

    def test_gateway_invalid_decision_becomes_abstain(self):
        gw = FederationGateway()
        k1 = _kernel("k1")
        k_unknown = _kernel("unknown")
        gw.register_kernel(k1)
        # unregistered kernel → treated as abstain
        result = gw.evaluate([_permit(k1), _deny(k_unknown)])
        # k_unknown is invalid → abstain, only k1 permits → 1/1 = 100% permit
        assert result.permitted

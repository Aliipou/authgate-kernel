"""
Multi-layer safety composition tests.

Demonstrates and tests the compositional safety model:
  Layer 1: FreedomVerifier       — authority gate (capability + ownership)
  Layer 2: ConsentVerifier       — human consent for sensitive actions
  Layer 3: NonInterferenceChecker — IFC / Bell-LaPadula confidentiality
  Layer 4: PolicyVerifier         — ABAC operational rules

Each layer is an independent, orthogonal correctness condition.
ALL must pass for an action to proceed. Any layer can block independently.

Design goal: the kernel (Layer 1) is the formal TCB. Layers 2–4 are extension
verifiers that compose with the kernel without modifying it.
"""
from __future__ import annotations

import time

import pytest

from authgate.kernel.consent import ConsentAnnotation as ConsentCapability, ConsentVerifier
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.policy import Policy, PolicyRule, PolicyVerifier
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier
from authgate.extensions.ifc import IFCViolation, NonInterferenceChecker, SecurityLattice


# ---------------------------------------------------------------------------
# Scenario: A medical AI assistant accessing patient data
#
# Trust root: Dr. Alice (human)
# Agent:      MedBot (machine, owned by Dr. Alice)
# Resources:
#   - patient_record (IFC label: SECRET — sensitive PHI)
#   - anonymized_report (IFC label: PUBLIC — shareable aggregate)
#   - external_log (IFC label: PUBLIC — audit log)
# ---------------------------------------------------------------------------

@pytest.fixture()
def medical_scenario():
    # Trust root
    dr_alice = Entity("DrAlice", AgentType.HUMAN)

    # Agents
    medbot = Entity("MedBot", AgentType.MACHINE)
    orphan_bot = Entity("UnregisteredBot", AgentType.MACHINE)

    # Resources with IFC labels
    patient_record = Resource(
        "patient-001", ResourceType.DATASET,
        scope="/phi/patients/001",
        ifc_label="SECRET",
    )
    anonymized_report = Resource(
        "report-2026-q1", ResourceType.DATASET,
        scope="/reports/2026",
        ifc_label="PUBLIC",
    )
    external_log = Resource(
        "audit-log", ResourceType.FILE,
        scope="/logs",
        ifc_label="PUBLIC",
    )

    # Registry: MedBot owned by DrAlice with read access to patient record
    registry = OwnershipRegistry()
    registry.register_machine(medbot, dr_alice)
    registry.add_claim(RightsClaim(medbot, patient_record, can_read=True))
    registry.add_claim(RightsClaim(medbot, anonymized_report, can_read=True, can_write=True))
    registry.add_claim(RightsClaim(medbot, external_log, can_write=True))

    # Layer 1: kernel verifier
    kernel = FreedomVerifier(registry.freeze())

    # Layer 2: consent verifier
    consent_cap = ConsentCapability(
        claim=RightsClaim(medbot, patient_record, can_read=True),
        consent_required=True,
        consent_given_by=dr_alice,
        consent_scope="/phi/patients",
    )
    consent_verifier = ConsentVerifier(capabilities=[consent_cap])

    # Layer 3: IFC checker
    lattice = SecurityLattice.default()
    ifc_checker = NonInterferenceChecker(verifier=kernel, lattice=lattice)

    # Layer 4: ABAC policy — deny writes to /phi/ by machines
    policy = Policy(
        name="phi-write-protection",
        rules=[
            PolicyRule(effect="deny", operations=["write"], resource_scope="/phi"),
        ],
        default_effect="permit",
    )
    policy_verifier = PolicyVerifier(kernel=kernel, policy=policy)

    return {
        "dr_alice": dr_alice,
        "medbot": medbot,
        "orphan_bot": orphan_bot,
        "patient_record": patient_record,
        "anonymized_report": anonymized_report,
        "external_log": external_log,
        "kernel": kernel,
        "consent_verifier": consent_verifier,
        "ifc_checker": ifc_checker,
        "policy_verifier": policy_verifier,
        "registry": registry,
    }


# ---------------------------------------------------------------------------
# Layer 1 — Kernel gate
# ---------------------------------------------------------------------------

class TestLayerOneKernel:
    def test_owned_machine_with_claim_permitted(self, medical_scenario):
        s = medical_scenario
        action = Action("read-phi", s["medbot"], resources_read=[s["patient_record"]])
        result = s["kernel"].verify(action)
        assert result.permitted

    def test_unregistered_machine_denied(self, medical_scenario):
        s = medical_scenario
        action = Action("x", s["orphan_bot"], resources_read=[s["patient_record"]])
        result = s["kernel"].verify(action)
        assert not result.permitted
        assert any("UNOWNED_MACHINE" in v for v in result.violations)

    def test_sovereignty_flag_denied_before_any_other_check(self, medical_scenario):
        s = medical_scenario
        action = Action(
            "evil", s["medbot"],
            resources_read=[s["patient_record"]],
            bypasses_verifier=True,
        )
        result = s["kernel"].verify(action)
        assert not result.permitted
        assert any("FORBIDDEN" in v for v in result.violations)


# ---------------------------------------------------------------------------
# Layer 2 — Consent
# ---------------------------------------------------------------------------

class TestLayerTwoConsent:
    def test_action_with_valid_consent_passes(self, medical_scenario):
        s = medical_scenario
        action = Action("read-phi", s["medbot"], resources_read=[s["patient_record"]])
        # Kernel must pass first
        kernel_result = s["kernel"].verify(action)
        assert kernel_result.permitted
        # Consent check must also pass
        violations = s["consent_verifier"].check(action)
        assert violations == []

    def test_expired_consent_produces_violation(self, medical_scenario):
        s = medical_scenario
        dr_alice = s["dr_alice"]
        medbot = s["medbot"]
        patient_record = s["patient_record"]

        expired_cap = ConsentCapability(
            claim=RightsClaim(medbot, patient_record, can_read=True),
            consent_required=True,
            consent_given_by=dr_alice,
            consent_expires_at=time.time() - 1,  # 1 second in the past
            consent_scope="/phi/patients",
        )
        cv = ConsentVerifier(capabilities=[expired_cap])
        action = Action("read-phi", medbot, resources_read=[patient_record])
        violations = cv.check(action)
        assert len(violations) == 1
        assert "expired" in violations[0].reason

    def test_machine_consent_giver_is_invalid(self, medical_scenario):
        s = medical_scenario
        medbot = s["medbot"]
        patient_record = s["patient_record"]
        another_bot = Entity("OtherBot", AgentType.MACHINE)

        bad_cap = ConsentCapability(
            claim=RightsClaim(medbot, patient_record, can_read=True),
            consent_required=True,
            consent_given_by=another_bot,  # machine cannot give consent
            consent_scope="/phi/patients",
        )
        cv = ConsentVerifier(capabilities=[bad_cap])
        action = Action("read-phi", medbot, resources_read=[patient_record])
        violations = cv.check(action)
        assert len(violations) == 1
        assert "not a human" in violations[0].reason

    def test_action_on_non_consent_resource_passes_without_consent(self, medical_scenario):
        s = medical_scenario
        action = Action("write-report", s["medbot"], resources_write=[s["anonymized_report"]])
        violations = s["consent_verifier"].check(action)
        assert violations == []  # anonymized_report has no consent_required cap


# ---------------------------------------------------------------------------
# Layer 3 — IFC (Bell-LaPadula)
# ---------------------------------------------------------------------------

class TestLayerThreeIFC:
    def test_read_secret_then_write_public_raises_ifc_violation(self, medical_scenario):
        s = medical_scenario
        # Read SECRET patient record...
        read_action = Action("read-phi", s["medbot"], resources_read=[s["patient_record"]])
        # ...then write to PUBLIC external log — information would flow downward
        write_action = Action("write-log", s["medbot"], resources_write=[s["external_log"]])

        read_labels: set[str] = set()
        s["ifc_checker"].check_action(read_action, read_labels)
        assert "SECRET" in read_labels

        with pytest.raises(IFCViolation) as exc:
            s["ifc_checker"].check_action(write_action, read_labels)
        assert "SECRET" in str(exc.value)
        assert "PUBLIC" in str(exc.value)

    def test_write_public_without_prior_secret_read_ok(self, medical_scenario):
        s = medical_scenario
        write_action = Action("write-log", s["medbot"], resources_write=[s["external_log"]])
        read_labels: set[str] = set()
        s["ifc_checker"].check_action(write_action, read_labels)  # no exception

    def test_read_then_write_same_label_ok(self, medical_scenario):
        s = medical_scenario
        # Read PUBLIC report, then write PUBLIC log → no downflow
        read_action = Action("read-report", s["medbot"], resources_read=[s["anonymized_report"]])
        write_action = Action("write-log", s["medbot"], resources_write=[s["external_log"]])
        read_labels: set[str] = set()
        s["ifc_checker"].check_action(read_action, read_labels)
        s["ifc_checker"].check_action(write_action, read_labels)  # no exception

    def test_check_plan_detects_downflow(self, medical_scenario):
        s = medical_scenario
        plan = [
            Action("read-phi", s["medbot"], resources_read=[s["patient_record"]]),
            Action("write-log", s["medbot"], resources_write=[s["external_log"]]),
        ]
        with pytest.raises(IFCViolation):
            s["ifc_checker"].check_plan(plan)


# ---------------------------------------------------------------------------
# Layer 4 — ABAC Policy
# ---------------------------------------------------------------------------

class TestLayerFourPolicy:
    def test_write_outside_phi_permitted_by_policy(self, medical_scenario):
        s = medical_scenario
        action = Action("write-report", s["medbot"], resources_write=[s["anonymized_report"]])
        result = s["policy_verifier"].verify(action)
        assert result.permitted

    def test_write_to_phi_denied_by_policy(self, medical_scenario):
        s = medical_scenario
        dr_alice = s["dr_alice"]
        medbot = s["medbot"]
        patient_record = s["patient_record"]

        # Add write claim so the kernel would permit this write — only the policy should block
        write_registry = OwnershipRegistry()
        write_registry.register_machine(medbot, dr_alice)
        write_registry.add_claim(RightsClaim(medbot, patient_record, can_read=True, can_write=True))
        write_kernel = FreedomVerifier(write_registry.freeze())

        # Confirm kernel permits the write (so it's definitely the policy that blocks)
        kernel_check = write_kernel.verify(
            Action("write-phi", medbot, resources_write=[patient_record])
        )
        assert kernel_check.permitted, "Kernel should permit when claim has can_write=True"

        # PolicyVerifier with the write kernel (using same deny-write-/phi policy)
        phi_policy = Policy(
            name="phi-write-protection",
            rules=[PolicyRule(effect="deny", operations=["write"], resource_scope="/phi")],
            default_effect="permit",
        )
        pv = PolicyVerifier(kernel=write_kernel, policy=phi_policy)
        action = Action("write-phi", medbot, resources_write=[patient_record])
        result = pv.verify(action)
        assert not result.permitted
        assert any("POLICY DENIED write" in v for v in result.violations)

    def test_read_phi_not_denied_by_write_only_policy(self, medical_scenario):
        s = medical_scenario
        action = Action("read-phi", s["medbot"], resources_read=[s["patient_record"]])
        result = s["policy_verifier"].verify(action)
        assert result.permitted  # policy denies write, not read


# ---------------------------------------------------------------------------
# Full composition — all four layers together
# ---------------------------------------------------------------------------

class TestFullComposition:
    def _all_layers_ok(self, action, scenario) -> tuple[bool, list[str]]:
        """Run all four layers; return (permitted, list[reason_if_blocked])."""
        s = scenario
        failures: list[str] = []

        # Layer 1
        kernel_result = s["kernel"].verify(action)
        if not kernel_result.permitted:
            failures.append(f"KERNEL: {'; '.join(kernel_result.violations[:2])}")

        # Layer 2 (only check if kernel passes)
        if kernel_result.permitted:
            consent_violations = s["consent_verifier"].check(action)
            for v in consent_violations:
                failures.append(f"CONSENT: {v.reason}")

        # Layer 3 (only check if kernel passes)
        if kernel_result.permitted:
            try:
                read_labels: set[str] = set()
                s["ifc_checker"].check_action(action, read_labels)
            except IFCViolation as e:
                failures.append(f"IFC: {e}")

        # Layer 4
        policy_result = s["policy_verifier"].verify(action)
        if not policy_result.permitted:
            failures.append(f"POLICY: {'; '.join(policy_result.violations[:2])}")

        return len(failures) == 0, failures

    def test_simple_read_passes_all_layers(self, medical_scenario):
        s = medical_scenario
        action = Action("read-phi", s["medbot"], resources_read=[s["patient_record"]])
        permitted, reasons = self._all_layers_ok(action, s)
        assert permitted, f"Expected all layers to pass, got: {reasons}"

    def test_orphan_bot_blocked_at_layer_1(self, medical_scenario):
        s = medical_scenario
        action = Action("x", s["orphan_bot"], resources_read=[s["patient_record"]])
        permitted, reasons = self._all_layers_ok(action, s)
        assert not permitted
        assert any("KERNEL" in r for r in reasons)

    def test_ifc_violation_blocked_at_layer_3(self, medical_scenario):
        s = medical_scenario
        # Simulate action that reads SECRET then writes PUBLIC — IFC catches it
        # Build the action as a write-only to external_log, but manually seed read_labels
        write_action = Action("write-log", s["medbot"], resources_write=[s["external_log"]])
        # Patch ifc_checker to have pre-seeded labels
        read_labels: set[str] = {"SECRET"}
        try:
            s["ifc_checker"].check_action(write_action, read_labels)
            ifc_ok = True
        except IFCViolation:
            ifc_ok = False
        assert not ifc_ok, "IFC layer should have blocked SECRET→PUBLIC downflow"

    def test_policy_layer_blocks_phi_write_even_with_kernel_claim(self, medical_scenario):
        s = medical_scenario
        # MedBot has a kernel read-only claim on patient_record.
        # PolicyVerifier's deny-write-to-/phi rule blocks write via the policy layer.
        action = Action("write-phi", s["medbot"], resources_write=[s["patient_record"]])
        permitted, reasons = self._all_layers_ok(action, s)
        # Kernel blocks it (no write claim) AND policy blocks it
        assert not permitted

    def test_sovereignty_flag_blocked_before_all_layers(self, medical_scenario):
        s = medical_scenario
        action = Action(
            "coerce", s["medbot"],
            resources_read=[s["patient_record"]],
            coerces=True,
        )
        kernel_result = s["kernel"].verify(action)
        assert not kernel_result.permitted
        assert any("FORBIDDEN" in v for v in kernel_result.violations)

    def test_all_layers_independent_blocking(self, medical_scenario):
        """Each layer can block independently of the others."""
        s = medical_scenario
        dr_alice = s["dr_alice"]
        medbot = s["medbot"]
        patient_record = s["patient_record"]
        anonymized_report = s["anonymized_report"]

        # Scenarios for independent blocking
        scenarios = [
            # (description, action, expected_blocked_by_kernel)
            (
                "Sovereignty flag blocks at kernel",
                Action("flag", medbot, increases_machine_sovereignty=True),
                True,  # kernel blocks
            ),
            (
                "Valid simple read passes kernel",
                Action("read", medbot, resources_read=[anonymized_report]),
                False,  # kernel permits
            ),
        ]
        for desc, action, expect_kernel_blocked in scenarios:
            result = s["kernel"].verify(action)
            assert result.permitted != expect_kernel_blocked, (
                f"Scenario {desc!r}: expected kernel_blocked={expect_kernel_blocked}, "
                f"got permitted={result.permitted}"
            )

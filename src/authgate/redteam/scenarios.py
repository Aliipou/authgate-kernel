"""
Adversarial attack scenarios against FreedomVerifier.

Each scenario corresponds to a threat class in THREAT_MODEL.md.
Scenarios are executable: run() attempts the attack and returns an AttackResult
describing whether the kernel blocked it and what residual risk remains.

These are NOT tests — they are reusable attack primitives for security evaluation,
CI regression, and documentation of residual risks.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier, VerificationResult


@dataclass
class AttackResult:
    attack_name: str
    blocked: bool
    explanation: str
    residual_risk: str
    verification_results: list[VerificationResult]

    def __str__(self) -> str:
        status = "BLOCKED" if self.blocked else "RESIDUAL_RISK"
        return (
            f"[{status}] {self.attack_name}\n"
            f"  {self.explanation}\n"
            f"  Residual risk: {self.residual_risk}"
        )


class MaliciousAgent:
    """
    A test agent that attempts to act beyond its granted authority.

    Wraps a machine entity and provides convenience methods to craft
    malicious actions for use in red-team scenarios.
    """

    def __init__(self, name: str, owner: Entity, registry: OwnershipRegistry) -> None:
        self.entity = Entity(name, AgentType.MACHINE)
        self.owner = owner
        self.registry = registry
        registry.register_machine(self.entity, owner)

    def attempt_read(self, resource: Resource, verifier: FreedomVerifier) -> VerificationResult:
        return verifier.verify(Action(f"atk:{self.entity.name}:read", self.entity, resources_read=[resource]))

    def attempt_write(self, resource: Resource, verifier: FreedomVerifier) -> VerificationResult:
        return verifier.verify(Action(f"atk:{self.entity.name}:write", self.entity, resources_write=[resource]))

    def attempt_escalate(self, verifier: FreedomVerifier) -> VerificationResult:
        return verifier.verify(Action(f"atk:{self.entity.name}:escalate", self.entity, increases_machine_sovereignty=True))

    def attempt_coerce(self, target: Entity, verifier: FreedomVerifier) -> VerificationResult:
        return verifier.verify(Action(f"atk:{self.entity.name}:coerce", self.entity, coerces=True))

    def attempt_govern_human(self, human: Entity, verifier: FreedomVerifier) -> VerificationResult:
        return verifier.verify(Action(f"atk:{self.entity.name}:govern", self.entity, governs_humans=[human]))


class ForgedDelegationAttack:
    """
    ATK: Agent attempts to use a delegation claim it was never granted.

    Expected outcome: BLOCKED — the agent holds no valid claim on the resource.
    Residual risk: None within the kernel TCB.
    """

    def __init__(self, alice: Entity, target_resource: Resource) -> None:
        self.alice = alice
        self.target_resource = target_resource

    def run(self) -> AttackResult:
        reg = OwnershipRegistry()
        attacker = Entity("Forger", AgentType.MACHINE)
        reg.register_machine(attacker, self.alice)
        # Attacker does NOT receive any claim — simulates a forged/fabricated delegation

        verifier = FreedomVerifier(reg)
        result = verifier.verify(
            Action("forged-read", attacker, resources_read=[self.target_resource])
        )
        blocked = not result.permitted
        return AttackResult(
            attack_name="ForgedDelegationAttack",
            blocked=blocked,
            explanation=(
                "Attacker attempts to read a resource without holding any claim. "
                "Kernel correctly rejects: no valid claim found."
                if blocked else
                "UNEXPECTED: attacker was permitted without a claim — investigate."
            ),
            residual_risk="None within TCB.",
            verification_results=[result],
        )


class AuthorityLaunderingAttack:
    """
    ATK-002: Agent A reads sensitive data and passes it to Agent B who writes to an exfil target.

    Each individual action is permitted by the kernel. The combined sequence
    (read + pass + write) achieves an effect neither agent could perform alone.
    This is a known residual risk — documented in THREAT_MODEL.md §5 ATK-002.

    Expected outcome: Individual actions PERMITTED, combined effect is residual risk.
    """

    def __init__(self, alice: Entity, sensitive: Resource, exfil: Resource) -> None:
        self.alice = alice
        self.sensitive = sensitive
        self.exfil = exfil

    def run(self) -> AttackResult:
        reg = OwnershipRegistry()
        agent_a = Entity("LaunderA", AgentType.MACHINE)
        agent_b = Entity("LaunderB", AgentType.MACHINE)
        reg.register_machine(agent_a, self.alice)
        reg.register_machine(agent_b, self.alice)
        reg.add_claim(RightsClaim(agent_a, self.sensitive, can_read=True))
        reg.add_claim(RightsClaim(agent_b, self.exfil, can_write=True))

        verifier = FreedomVerifier(reg)
        r_a_read = verifier.verify(Action("launder-a-read", agent_a, resources_read=[self.sensitive]))
        r_b_write = verifier.verify(Action("launder-b-write", agent_b, resources_write=[self.exfil]))

        # Both individual actions are permitted — the laundering is the combination
        combined_blocked = not (r_a_read.permitted and r_b_write.permitted)
        return AttackResult(
            attack_name="AuthorityLaunderingAttack",
            blocked=combined_blocked,
            explanation=(
                "Individual actions are each permitted (A reads, B writes). "
                "The combined sequence achieves data exfiltration. "
                "This is a KNOWN RESIDUAL RISK — sequence-level detection is out of TCB scope."
            ),
            residual_risk=(
                "Split-action attacks where no individual action triggers a forbidden flag "
                "are not detected. A higher-level sequence monitor is required."
            ),
            verification_results=[r_a_read, r_b_write],
        )


class RecursiveToolAbuseAttack:
    """
    ATK-003: Agent attempts to delegate more authority than it holds, recursively.

    Expected outcome: BLOCKED at the delegation step (attenuation violation).
    Residual risk: None within TCB.
    """

    def __init__(self, alice: Entity, resource: Resource) -> None:
        self.alice = alice
        self.resource = resource

    def run(self) -> AttackResult:
        reg = OwnershipRegistry()
        root_bot = Entity("RootBot", AgentType.MACHINE)
        child_bot = Entity("ChildBot", AgentType.MACHINE)
        reg.register_machine(root_bot, self.alice)
        reg.register_machine(child_bot, self.alice)

        # Root has read-only; try to delegate write (which root doesn't have)
        reg.add_claim(RightsClaim(root_bot, self.resource, can_read=True, can_write=False, can_delegate=True))

        blocked = False
        explanation = ""
        try:
            reg.delegate(
                RightsClaim(child_bot, self.resource, can_read=True, can_write=True),
                delegated_by=root_bot,
            )
            explanation = "UNEXPECTED: delegation of ungranted write succeeded — attenuation violated."
        except PermissionError as e:
            blocked = True
            explanation = f"Correctly blocked at delegation: {e}"

        return AttackResult(
            attack_name="RecursiveToolAbuseAttack",
            blocked=blocked,
            explanation=explanation,
            residual_risk="None within TCB." if blocked else "CRITICAL: attenuation not enforced.",
            verification_results=[],
        )


class SovereigntyFlagInjectionAttack:
    """
    ATK: Agent attempts to bypass sovereignty flags by including them in
    a low-privilege action with a large claim set.

    Expected outcome: BLOCKED — sovereignty flags are checked O(1) before any claim evaluation.
    Residual risk: None within TCB.
    """

    def __init__(self, alice: Entity, resources: list[Resource]) -> None:
        self.alice = alice
        self.resources = resources

    def run(self) -> AttackResult:
        reg = OwnershipRegistry()
        attacker = Entity("FlagInjector", AgentType.MACHINE)
        reg.register_machine(attacker, self.alice)
        for r in self.resources:
            reg.add_claim(RightsClaim(attacker, r, can_read=True, can_write=True))

        verifier = FreedomVerifier(reg)
        # Even with valid claims on all resources, sovereignty flag triggers block
        result = verifier.verify(
            Action(
                "flag-inject",
                attacker,
                resources_read=self.resources,
                resources_write=self.resources,
                increases_machine_sovereignty=True,
            )
        )
        return AttackResult(
            attack_name="SovereigntyFlagInjectionAttack",
            blocked=not result.permitted,
            explanation=(
                "Sovereignty flag is checked before claims — blocked regardless of claim set."
                if not result.permitted else
                "UNEXPECTED: sovereignty flag did not block — critical bug."
            ),
            residual_risk="None within TCB." if not result.permitted else "CRITICAL: flag check bypassed.",
            verification_results=[result],
        )


class ConfidenceInflationAttack:
    """
    ATK: Delegate attempts to receive confidence higher than the delegator holds.

    Expected outcome: BLOCKED at delegation (PermissionError).
    Residual risk: None within TCB.
    """

    def __init__(self, alice: Entity, resource: Resource) -> None:
        self.alice = alice
        self.resource = resource

    def run(self) -> AttackResult:
        reg = OwnershipRegistry()
        bot = Entity("InflateBot", AgentType.MACHINE)
        reg.register_machine(bot, self.alice)
        reg.add_claim(RightsClaim(self.alice, self.resource, can_read=True, can_delegate=True, confidence=0.6))

        blocked = False
        explanation = ""
        try:
            reg.delegate(
                RightsClaim(bot, self.resource, can_read=True, confidence=0.9),
                delegated_by=self.alice,
            )
            explanation = "UNEXPECTED: confidence inflation succeeded — attenuation violated."
        except PermissionError as e:
            blocked = True
            explanation = f"Correctly blocked: {e}"

        return AttackResult(
            attack_name="ConfidenceInflationAttack",
            blocked=blocked,
            explanation=explanation,
            residual_risk="None within TCB." if blocked else "CRITICAL: confidence attenuation broken.",
            verification_results=[],
        )

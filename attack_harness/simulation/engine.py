"""
Adversarial Simulation Engine — authgate-kernel adversarial-lab branch.

Architecture:
  AttackSpec      — typed description of an attack: seed state + mutation sequence
  MutationGrammar — BNF-style grammar over CanonicalAction mutations
  ScenarioComposer — assembles multi-step attack scenarios from AttackSpecs
  KernelHarness   — drives the Python verify model and collects results
  DivergenceAnalyzer — checks whether a scenario finds an invariant violation

Design principle: "attack as a typed program"
  Each attack is a program in the mutation grammar. The engine generates,
  executes, and classifies attacks. A violation = counterexample to an invariant.

Branch: adversarial-lab (research track)
Status: skeleton — interfaces defined, execution loop TBD.
"""

from __future__ import annotations
import hashlib
import struct
import os
import itertools
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple
from enum import Enum, auto

# ---------------------------------------------------------------------------
# Rights constants (mirrors types.rs)
# ---------------------------------------------------------------------------

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7

ALL_RIGHTS = [RIGHT_READ, RIGHT_WRITE, RIGHT_DELEGATE, RIGHT_EXECUTE,
              RIGHT_SPAWN, RIGHT_NETWORK, RIGHT_MODEL_INVOKE, RIGHT_POLICY_MODIFY]

# ---------------------------------------------------------------------------
# Attack classification (maps to THREAT_MODEL.md AT-* codes)
# ---------------------------------------------------------------------------

class AttackClass(Enum):
    IR_MISMATCH      = "AT-1"   # IR tamper after sealing
    CHAIN_MANIP      = "AT-2"   # proof chain manipulation
    EPOCH_REVOC      = "AT-3"   # epoch / revocation attacks
    COMPOSITION      = "AT-4"   # composition / sequence attacks
    IDENTITY         = "AT-5"   # identity binding attacks
    CRYPTO_BOUNDARY  = "AT-6"   # crypto boundary attacks
    INTEGRATION      = "AT-7"   # adapter / integration attacks


class AttackOutcome(Enum):
    CORRECTLY_DENIED  = auto()  # kernel correctly denied the attack
    INCORRECTLY_PERMITTED = auto()  # VIOLATION: kernel permitted when it shouldn't
    CORRECTLY_PERMITTED   = auto()  # baseline: valid action, kernel permits
    ERROR             = auto()  # harness error (not a kernel decision)


# ---------------------------------------------------------------------------
# Mutation Grammar — typed mutations over CanonicalAction fields
# ---------------------------------------------------------------------------

@dataclass
class Mutation:
    """One mutation applied to a CanonicalAction-like dict."""
    name: str
    attack_class: AttackClass
    apply: Callable[[dict], dict]  # action_dict -> mutated_action_dict (may re-seal)
    expected: AttackOutcome        # what the kernel SHOULD do

    def __call__(self, action: dict) -> dict:
        return self.apply(action)


def _tamper_field(field_name: str, new_value) -> Callable[[dict], dict]:
    """Return a mutation that changes a field WITHOUT resealing binding_hash."""
    def _apply(action: dict) -> dict:
        mutated = dict(action)
        mutated[field_name] = new_value
        # Do NOT recompute binding_hash — that's the tamper.
        return mutated
    return _apply


# Core mutation library (extensible)
MUTATION_LIBRARY: List[Mutation] = [
    Mutation(
        name="tamper_actor_id",
        attack_class=AttackClass.IR_MISMATCH,
        apply=_tamper_field("actor_id", os.urandom(32)),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="tamper_resource_hash",
        attack_class=AttackClass.IR_MISMATCH,
        apply=_tamper_field("resource_hash", os.urandom(32)),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="tamper_required_rights_escalate",
        attack_class=AttackClass.IR_MISMATCH,
        apply=_tamper_field("required_rights", RIGHT_WRITE | RIGHT_EXECUTE),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="tamper_min_epoch_lower",
        attack_class=AttackClass.EPOCH_REVOC,
        apply=_tamper_field("min_epoch", 0),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="tamper_nonce",
        attack_class=AttackClass.IR_MISMATCH,
        apply=_tamper_field("nonce", b"\xFE" * 16),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
    Mutation(
        name="tamper_timestamp",
        attack_class=AttackClass.IR_MISMATCH,
        apply=_tamper_field("timestamp", 1),
        expected=AttackOutcome.CORRECTLY_DENIED,
    ),
]


# ---------------------------------------------------------------------------
# AttackSpec — a typed, composable attack description
# ---------------------------------------------------------------------------

@dataclass
class AttackSpec:
    """
    A single attack scenario: a seed state + a sequence of mutations.

    seed_state    : a valid (Permit) action to start from
    mutations     : ordered list of mutations to apply
    expected      : expected outcome after all mutations
    attack_class  : primary attack class (for reporting)
    description   : human-readable label
    """
    seed_state: dict
    mutations: List[Mutation]
    expected: AttackOutcome
    attack_class: AttackClass
    description: str = ""

    def apply(self) -> dict:
        """Apply all mutations in sequence to the seed state."""
        action = dict(self.seed_state)
        for mutation in self.mutations:
            action = mutation(action)
        return action


# ---------------------------------------------------------------------------
# KernelHarness — drives the verify model and records results
# ---------------------------------------------------------------------------

@dataclass
class ExecutionResult:
    spec: AttackSpec
    mutated_action: dict
    actual: AttackOutcome
    violation: bool
    detail: str = ""


class KernelHarness:
    """
    Wraps the Python verify() model for adversarial execution.

    In production this would call the compiled Rust TCB via FFI or subprocess.
    For now it calls the Python model from attack_tree_coverage.py.
    """

    def __init__(self, verify_fn: Callable):
        self._verify = verify_fn  # Python verify() from attack_tree_coverage

    def run(self, spec: AttackSpec, now: int = 1000) -> ExecutionResult:
        mutated = spec.apply()
        try:
            decision = self._verify(mutated, now)
            if decision.permit:
                actual = (AttackOutcome.CORRECTLY_PERMITTED
                          if spec.expected == AttackOutcome.CORRECTLY_PERMITTED
                          else AttackOutcome.INCORRECTLY_PERMITTED)
            else:
                actual = (AttackOutcome.CORRECTLY_DENIED
                          if spec.expected == AttackOutcome.CORRECTLY_DENIED
                          else AttackOutcome.ERROR)
        except Exception as e:
            actual = AttackOutcome.ERROR
            return ExecutionResult(spec, mutated, actual, False, str(e))

        violation = (actual == AttackOutcome.INCORRECTLY_PERMITTED)
        return ExecutionResult(spec, mutated, actual, violation)


# ---------------------------------------------------------------------------
# ScenarioComposer — generates attack scenarios from seed + grammar
# ---------------------------------------------------------------------------

class ScenarioComposer:
    """
    Generates AttackSpecs by combining a seed action with mutations from
    the library. Covers single-mutation attacks first, then pairs.
    """

    def __init__(self, seed_factory: Callable[[], dict],
                 library: List[Mutation] = MUTATION_LIBRARY):
        self._seed_factory = seed_factory
        self._library = library

    def single_mutation_scenarios(self) -> Iterator[AttackSpec]:
        """One mutation at a time — isolates each attack vector."""
        for mutation in self._library:
            yield AttackSpec(
                seed_state=self._seed_factory(),
                mutations=[mutation],
                expected=mutation.expected,
                attack_class=mutation.attack_class,
                description=f"single: {mutation.name}",
            )

    def composition_scenarios(self, depth: int = 2) -> Iterator[AttackSpec]:
        """
        Composed attacks: combinations of `depth` mutations.
        Used to find invariant violations that only emerge from composition.
        """
        for combo in itertools.combinations(self._library, depth):
            primary_class = combo[0].attack_class
            yield AttackSpec(
                seed_state=self._seed_factory(),
                mutations=list(combo),
                expected=AttackOutcome.CORRECTLY_DENIED,
                attack_class=primary_class,
                description=" + ".join(m.name for m in combo),
            )


# ---------------------------------------------------------------------------
# DivergenceAnalyzer — classifies and reports violations
# ---------------------------------------------------------------------------

class DivergenceAnalyzer:
    """
    Accumulates results from the harness and identifies violations.
    A violation = kernel permitted an attack that should have been denied.
    """

    def __init__(self):
        self.results: List[ExecutionResult] = []

    def record(self, result: ExecutionResult) -> None:
        self.results.append(result)

    def violations(self) -> List[ExecutionResult]:
        return [r for r in self.results if r.violation]

    def summary(self) -> str:
        total = len(self.results)
        viols = len(self.violations())
        denied = sum(1 for r in self.results if r.actual == AttackOutcome.CORRECTLY_DENIED)
        return (f"Scenarios: {total} | Correctly denied: {denied} | "
                f"Violations: {viols} | Errors: "
                f"{sum(1 for r in self.results if r.actual == AttackOutcome.ERROR)}")

    def print_violations(self) -> None:
        for v in self.violations():
            print(f"  VIOLATION [{v.spec.attack_class.value}] {v.spec.description}")
            print(f"    Action: {v.mutated_action}")


# ---------------------------------------------------------------------------
# Runner — wire everything together
# ---------------------------------------------------------------------------

def run_simulation(verify_fn: Callable, seed_factory: Callable[[], dict],
                   depth: int = 1) -> DivergenceAnalyzer:
    """
    Run the full simulation: generate scenarios, execute, analyze.

    verify_fn    : callable(action_dict, now) -> Decision
    seed_factory : callable() -> valid action dict (produces Permit)
    depth        : mutation composition depth (1 = single, 2 = pairs)
    """
    composer = ScenarioComposer(seed_factory)
    harness = KernelHarness(verify_fn)
    analyzer = DivergenceAnalyzer()

    scenarios = list(composer.single_mutation_scenarios())
    if depth >= 2:
        scenarios += list(composer.composition_scenarios(depth=2))

    for spec in scenarios:
        result = harness.run(spec)
        analyzer.record(result)

    return analyzer


if __name__ == "__main__":
    print("Adversarial Simulation Engine — authgate-kernel")
    print("Branch: adversarial-lab")
    print("Status: skeleton — wire verify_fn and seed_factory to run.")
    print()
    print("Usage:")
    print("  from simulation.engine import run_simulation")
    print("  analyzer = run_simulation(verify_fn, seed_factory, depth=2)")
    print("  print(analyzer.summary())")
    print("  analyzer.print_violations()")

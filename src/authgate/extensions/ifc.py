"""
extensions/ifc.py — Information Flow Control for the Freedom Kernel.

Implements Bell-LaPadula style non-interference as an extension on top of
the permission kernel. The kernel (Permitted) is a necessary precondition;
the IFC checker is a separate correctness pass on top.

The kernel answers: does the agent hold the authority?
The IFC checker answers: would this sequence of reads/writes leak information
from a higher security label to a lower one?

Usage:
    from authgate.extensions.ifc import NonInterferenceChecker, SecurityLattice

    checker = NonInterferenceChecker(verifier)
    checker.check_plan(actions)   # raises IFCViolation on downward flow
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class IFCViolation(Exception):
    """Raised when an action or plan would violate non-interference."""

    def __init__(
        self,
        msg: str,
        action_id: str = "",
        source_label: str = "",
        sink_label: str = "",
    ) -> None:
        super().__init__(msg)
        self.action_id = action_id
        self.source_label = source_label
        self.sink_label = sink_label


@dataclass
class SecurityLattice:
    """
    Defines a security-label ordering for Bell-LaPadula non-interference.

    flows_to maps each label to the set of labels it may flow INTO.
    E.g., PUBLIC info can flow into PUBLIC, INTERNAL, or SECRET containers
    (higher confidentiality sinks are fine). SECRET info can only flow into
    SECRET containers (it must not leak downward).

    The default 3-level lattice: PUBLIC < INTERNAL < SECRET
    """

    flows_to: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def default(cls) -> SecurityLattice:
        """Standard 3-level lattice: PUBLIC < INTERNAL < SECRET."""
        return cls(
            flows_to={
                "": ["", "PUBLIC", "INTERNAL", "SECRET"],
                "PUBLIC": ["PUBLIC", "INTERNAL", "SECRET"],
                "INTERNAL": ["INTERNAL", "SECRET"],
                "SECRET": ["SECRET"],
            }
        )

    def can_flow(self, source_label: str, sink_label: str) -> bool:
        """Return True iff data from source_label may flow into sink_label."""
        allowed = self.flows_to.get(source_label, [source_label])
        return sink_label in allowed


@dataclass
class NonInterferenceChecker:
    """
    Checks that a sequence of actions does not cause downward information flow.

    Rule (Bell-LaPadula applied to agentic execution):
      Track the set of labels read by the agent across the plan.
      For each write, verify the write's label can receive data from ALL
      previously-read labels. If any read label is higher than the write label,
      information would flow downward — raise IFCViolation.

    This runs AFTER the kernel gate. The kernel is a necessary condition;
    IFC is an orthogonal correctness condition.
    """

    verifier: Any
    lattice: SecurityLattice = field(default_factory=SecurityLattice.default)

    def check_action(
        self, action: Any, read_labels_so_far: set[str] | None = None
    ) -> None:
        """
        Check a single action for IFC violations given previously-read labels.

        Updates read_labels_so_far in-place with labels from this action's reads.
        Raises IFCViolation if any write would receive information from a higher label.
        """
        if read_labels_so_far is None:
            read_labels_so_far = set()

        for resource in getattr(action, "resources_read", []):
            label = getattr(resource, "ifc_label", "") or ""
            read_labels_so_far.add(label)

        for resource in getattr(action, "resources_write", []):
            write_label = getattr(resource, "ifc_label", "") or ""
            for read_label in read_labels_so_far:
                if not self.lattice.can_flow(read_label, write_label):
                    raise IFCViolation(
                        f"IFC violation in '{action.action_id}': agent has read "
                        f"'{read_label}' resource but attempts to write "
                        f"'{write_label}' resource — information would flow downward.",
                        action_id=action.action_id,
                        source_label=read_label,
                        sink_label=write_label,
                    )

    def check_plan(self, actions: list[Any]) -> None:
        """
        Check a sequence of actions for IFC violations.

        Accumulates read labels across the plan (conservative approximation:
        once a label is read, it taints all subsequent writes).
        Raises IFCViolation at the first violation encountered.
        """
        read_labels_so_far: set[str] = set()
        for action in actions:
            self.check_action(action, read_labels_so_far)

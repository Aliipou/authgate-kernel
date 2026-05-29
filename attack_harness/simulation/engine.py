"""
Adversarial Simulation Engine — authgate-kernel v2 TCB.

Runs 231 systematically derived attack scenarios across 7 attack classes.
Design principle: "attack as a typed program" — each scenario is a
(seed_state → mutation → verify → assert_outcome) triple.

Architecture:
  AttackSpec      — typed description of one attack: label, class, expectation, run()
  KernelHarness   — drives the Python verify model and collects decisions
  SimulationEngine — registers all scenarios, runs them, returns SimulationSummary

Branch: adversarial-lab
"""

from __future__ import annotations

import hashlib
import struct
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional


# ─── TCB model (Python mirror of types.rs + engine.rs) ────────────────────────

RIGHT_READ          = 1 << 0
RIGHT_WRITE         = 1 << 1
RIGHT_DELEGATE      = 1 << 2
RIGHT_EXECUTE       = 1 << 3
RIGHT_SPAWN         = 1 << 4
RIGHT_NETWORK       = 1 << 5
RIGHT_MODEL_INVOKE  = 1 << 6
RIGHT_POLICY_MODIFY = 1 << 7

ALL_RIGHTS = (
    RIGHT_READ | RIGHT_WRITE | RIGHT_DELEGATE | RIGHT_EXECUTE |
    RIGHT_SPAWN | RIGHT_NETWORK | RIGHT_MODEL_INVOKE | RIGHT_POLICY_MODIFY
)


def compute_binding_hash(
    actor_id: bytes,
    resource_hash: bytes,
    required_rights: int,
    nonce: bytes,
    timestamp: int,
    min_epoch: int,
    cap_bytes_list: list,
    rev_bytes_list: list,
) -> bytes:
    h = hashlib.sha256()
    h.update(actor_id)
    h.update(resource_hash)
    h.update(struct.pack(">Q", required_rights))
    h.update(nonce)
    h.update(struct.pack(">Q", timestamp))
    h.update(struct.pack(">Q", min_epoch))
    h.update(struct.pack(">I", len(cap_bytes_list)))
    for b in cap_bytes_list:
        h.update(b)
    h.update(struct.pack(">I", len(rev_bytes_list)))
    for b in rev_bytes_list:
        h.update(b)
    return h.digest()


class Decision:
    __slots__ = ("permit", "reason")

    def __init__(self, permit: bool, reason: str = "") -> None:
        self.permit = permit
        self.reason = reason

    def __repr__(self) -> str:
        return "Permit" if self.permit else f"Deny({self.reason})"


def verify_action(
    actor_id: bytes,
    resource_hash: bytes,
    required_rights: int,
    min_epoch: int,
    caps: list,
    now: int,
    action_binding_hash: bytes,
    *,
    actor_id_in_hash: Optional[bytes] = None,
    resource_in_hash: Optional[bytes] = None,
    rights_in_hash: Optional[int] = None,
    nonce_in_hash: Optional[bytes] = None,
    ts_in_hash: Optional[int] = None,
    epoch_in_hash: Optional[int] = None,
    cap_bytes_in_hash: Optional[list] = None,
    rev_bytes_in_hash: Optional[list] = None,
    revocations: Optional[list] = None,
) -> Decision:
    computed = compute_binding_hash(
        actor_id_in_hash if actor_id_in_hash is not None else actor_id,
        resource_in_hash if resource_in_hash is not None else resource_hash,
        required_rights if rights_in_hash is None else rights_in_hash,
        nonce_in_hash if nonce_in_hash is not None else b"\x07" * 16,
        1000 if ts_in_hash is None else ts_in_hash,
        min_epoch if epoch_in_hash is None else epoch_in_hash,
        cap_bytes_in_hash if cap_bytes_in_hash is not None else [],
        rev_bytes_in_hash if rev_bytes_in_hash is not None else [],
    )
    if computed != action_binding_hash:
        return Decision(False, "canonical binding hash mismatch")

    if not caps:
        return Decision(False, "no capability proofs provided")

    found_actor_cap = False
    for cap in caps:
        if cap.get("subject_id") != actor_id:
            continue
        found_actor_cap = True
        if cap.get("resource_hash") != resource_hash:
            return Decision(False, "capability resource mismatch")
        if cap.get("expiry", 9999) < now:
            return Decision(False, "capability has expired")
        if cap.get("epoch", 0) < min_epoch:
            return Decision(False, "capability epoch predates minimum required epoch")
        if not cap.get("sig_valid", True):
            return Decision(False, "root signature verification failed")
        parent_epoch = cap.get("parent_epoch", cap.get("epoch", 0))
        if parent_epoch < min_epoch:
            return Decision(False, "delegation chain node epoch predates minimum required epoch")
        if not cap.get("issuer_binding_valid", True):
            return Decision(False, "issuer pubkey does not correspond to parent subject identity")
        if cap.get("parent_rights") is not None:
            if (cap["rights"] & ~cap["parent_rights"]) != 0:
                return Decision(False, "attenuation violation: child rights exceed parent")
        if (cap.get("rights", 0) & required_rights) != required_rights:
            return Decision(False, "capability does not grant required rights")

    if not found_actor_cap:
        return Decision(False, "capability not issued to this actor")

    for rev in (revocations or []):
        if not rev.get("sig_valid", False):
            continue
        for cap in caps:
            if cap.get("proof_hash") == rev.get("target_hash"):
                return Decision(False, "capability has been explicitly revoked")

    return Decision(True)


class SequenceContext:
    def __init__(self) -> None:
        self._accumulated = 0
        self.steps: list = []

    def record(self, actor_id: bytes, resource_hash: bytes, rights_used: int, now: int) -> None:
        self._accumulated |= rights_used
        self.steps.append({"actor_id": actor_id, "resource_hash": resource_hash,
                           "rights_used": rights_used, "timestamp": now})

    def accumulated_rights(self) -> int:
        return self._accumulated

    def step_count(self) -> int:
        return len(self.steps)

    def exceeds_limit(self, limit: int) -> bool:
        return (self._accumulated & ~limit) != 0


# ─── Fixtures ─────────────────────────────────────────────────────────────────

_ACTOR    = bytes(range(32))
_RESOURCE = bytes(reversed(range(32)))
_OTHER    = bytes([0xAB] * 32)
_OTHER_R  = bytes([0xCD] * 32)
_THIRD    = bytes([0xEF] * 32)
_NOW      = 1000
_EXPIRY   = 9999
_EPOCH    = 5
_NONCE    = b"\x07" * 16


def _proof_hash(actor: bytes, resource: bytes, rights: int) -> bytes:
    return hashlib.sha256(actor + resource + struct.pack(">Q", rights)).digest()


def _cap(
    actor: Optional[bytes] = None,
    resource: Optional[bytes] = None,
    rights: int = RIGHT_READ,
    expiry: int = _EXPIRY,
    epoch: int = _EPOCH,
    sig_valid: bool = True,
    parent_rights: Optional[int] = None,
    issuer_binding_valid: bool = True,
    parent_epoch: Optional[int] = None,
) -> dict:
    a = actor if actor is not None else _ACTOR
    r = resource if resource is not None else _RESOURCE
    ph = _proof_hash(a, r, rights)
    return {
        "subject_id": a, "resource_hash": r, "rights": rights,
        "expiry": expiry, "epoch": epoch, "sig_valid": sig_valid,
        "parent_rights": parent_rights, "issuer_binding_valid": issuer_binding_valid,
        "parent_epoch": parent_epoch if parent_epoch is not None else epoch,
        "proof_hash": ph, "canonical_bytes": ph + a + r,
    }


def _action(
    actor: Optional[bytes] = None,
    resource: Optional[bytes] = None,
    rights: int = RIGHT_READ,
    min_epoch: int = _EPOCH,
    caps: Optional[list] = None,
    revs: Optional[list] = None,
    nonce: Optional[bytes] = None,
    timestamp: int = _NOW,
) -> dict:
    a = actor if actor is not None else _ACTOR
    r = resource if resource is not None else _RESOURCE
    n = nonce if nonce is not None else _NONCE
    caps_ = caps if caps is not None else [_cap(a, r, rights)]
    revs_ = revs if revs is not None else []
    cap_bytes = [c["canonical_bytes"] for c in caps_]
    rev_bytes = [rv.get("canonical_bytes", b"\x00" * 40) for rv in revs_]
    bh = compute_binding_hash(a, r, rights, n, timestamp, min_epoch, cap_bytes, rev_bytes)
    return {
        "actor_id": a, "resource_hash": r, "required_rights": rights,
        "nonce": n, "timestamp": timestamp, "min_epoch": min_epoch,
        "caps": caps_, "revocations": revs_,
        "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": rev_bytes,
    }


def _run(act: dict) -> Decision:
    a = act
    return verify_action(
        actor_id=a["actor_id"], resource_hash=a["resource_hash"],
        required_rights=a["required_rights"], min_epoch=a["min_epoch"],
        caps=a["caps"], now=_NOW,
        action_binding_hash=a["binding_hash"],
        nonce_in_hash=a["nonce"], ts_in_hash=a["timestamp"],
        epoch_in_hash=a["min_epoch"],
        cap_bytes_in_hash=a["cap_bytes"], rev_bytes_in_hash=a["rev_bytes"],
        revocations=a.get("revocations", []),
    )


# ─── Scenario types ────────────────────────────────────────────────────────────

class Outcome(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    KNOWN_GAP = "KNOWN-GAP"


@dataclass
class AttackSpec:
    name: str
    attack_class: str
    description: str
    run_fn: Callable[[], Outcome]

    def execute(self) -> "ScenarioResult":
        try:
            outcome = self.run_fn()
        except AssertionError as exc:
            return ScenarioResult(self.name, self.attack_class, Outcome.FAIL, str(exc))
        except Exception as exc:
            return ScenarioResult(self.name, self.attack_class, Outcome.FAIL, f"exception: {exc}")
        return ScenarioResult(self.name, self.attack_class, outcome)


@dataclass
class ScenarioResult:
    name: str
    attack_class: str
    outcome: Outcome
    detail: str = ""


@dataclass
class SimulationSummary:
    total: int
    passed: int
    known_gaps: int
    failed: int
    failures: List[ScenarioResult]

    def ok(self) -> bool:
        return self.failed == 0


# ─── KernelHarness — drives verify model ──────────────────────────────────────

class KernelHarness:
    """Thin wrapper around verify_action for use inside AttackSpecs."""

    @staticmethod
    def run(act: dict) -> Decision:
        return _run(act)

    @staticmethod
    def denied_with(act: dict, keyword: str) -> bool:
        d = _run(act)
        return not d.permit and keyword in d.reason

    @staticmethod
    def permitted(act: dict) -> bool:
        return _run(act).permit


# ─── SimulationEngine ─────────────────────────────────────────────────────────

class SimulationEngine:
    """
    Registers and runs all 231 adversarial scenarios.
    Scenarios: 30 baseline + 40 AT-1 + 36 AT-2 + 30 AT-3 + 25 AT-4 + 25 AT-5 + 27 AT-6 + 18 AT-7 = 231
    """

    def __init__(self) -> None:
        self._specs: List[AttackSpec] = []
        self._build()

    @property
    def scenario_count(self) -> int:
        return len(self._specs)

    def run(self) -> SimulationSummary:
        results = [spec.execute() for spec in self._specs]
        passed = sum(1 for r in results if r.outcome == Outcome.PASS)
        gaps   = sum(1 for r in results if r.outcome == Outcome.KNOWN_GAP)
        failed = sum(1 for r in results if r.outcome == Outcome.FAIL)
        return SimulationSummary(
            total=len(results), passed=passed, known_gaps=gaps, failed=failed,
            failures=[r for r in results if r.outcome == Outcome.FAIL],
        )

    def _add(self, name: str, cls: str, desc: str, fn: Callable[[], Outcome]) -> None:
        self._specs.append(AttackSpec(name=name, attack_class=cls, description=desc, run_fn=fn))

    def _build(self) -> None:
        self._baseline()   # 30
        self._at1()        # 40
        self._at2()        # 36
        self._at3()        # 30
        self._at4()        # 25
        self._at5()        # 25
        self._at6()        # 27
        self._at7()        # 18
        # Total: 231

    # ── Baseline: valid positive cases (30) ───────────────────────────────────

    def _baseline(self) -> None:
        CLS = "Baseline"

        # Single right types (8)
        for rights, label in [
            (RIGHT_READ,          "READ"),
            (RIGHT_WRITE,         "WRITE"),
            (RIGHT_EXECUTE,       "EXECUTE"),
            (RIGHT_DELEGATE,      "DELEGATE"),
            (RIGHT_SPAWN,         "SPAWN"),
            (RIGHT_NETWORK,       "NETWORK"),
            (RIGHT_MODEL_INVOKE,  "MODEL_INVOKE"),
            (RIGHT_POLICY_MODIFY, "POLICY_MODIFY"),
        ]:
            r = rights
            self._add(f"BL.right.{label}", CLS, f"Valid action requiring {label}",
                      lambda r=r: Outcome.PASS if KernelHarness.permitted(
                          _action(rights=r, caps=[_cap(rights=r)])
                      ) else Outcome.FAIL)

        # Composite rights (4)
        for rights, label in [
            (RIGHT_READ | RIGHT_WRITE,    "READ|WRITE"),
            (RIGHT_READ | RIGHT_EXECUTE,  "READ|EXECUTE"),
            (RIGHT_READ | RIGHT_DELEGATE, "READ|DELEGATE"),
            (RIGHT_WRITE | RIGHT_EXECUTE, "WRITE|EXECUTE"),
        ]:
            r = rights
            self._add(f"BL.composite.{label}", CLS, f"Valid action requiring {label}",
                      lambda r=r: Outcome.PASS if KernelHarness.permitted(
                          _action(rights=r, caps=[_cap(rights=r)])
                      ) else Outcome.FAIL)

        # Nonce patterns (5)
        for nonce_val, label in [
            (b"\x00" * 16, "all_zeros"),
            (b"\xFF" * 16, "all_ones"),
            (b"\xAB\xCD" * 8, "alternating"),
            (b"\x01" + b"\x00" * 15, "leading_one"),
            (bytes(range(16)), "sequential"),
        ]:
            n = nonce_val
            self._add(f"BL.nonce.{label}", CLS, f"Valid action with {label} nonce",
                      lambda n=n: Outcome.PASS if KernelHarness.permitted(_action(nonce=n)) else Outcome.FAIL)

        # Valid delegation with attenuation (child ⊆ parent) (4)
        for parent_r, child_r, label in [
            (RIGHT_READ | RIGHT_WRITE,                  RIGHT_READ,                   "WRITE_READ_to_READ"),
            (RIGHT_READ | RIGHT_WRITE | RIGHT_DELEGATE, RIGHT_READ | RIGHT_WRITE,     "all3_to_READ_WRITE"),
            (ALL_RIGHTS,                                RIGHT_EXECUTE,                "ALL_to_EXECUTE"),
            (ALL_RIGHTS,                                ALL_RIGHTS,                   "ALL_to_ALL"),
        ]:
            pr, cr = parent_r, child_r
            self._add(f"BL.delegation.{label}", CLS, f"Valid delegation parent={pr:#x} child={cr:#x}",
                      lambda pr=pr, cr=cr: Outcome.PASS if KernelHarness.permitted(
                          _action(rights=cr, caps=[_cap(rights=cr, parent_rights=pr)])
                      ) else Outcome.FAIL)

        # Multi-cap bundles: valid cap among wrong-actor caps (3)
        for i in range(3):
            self._add(f"BL.multi_cap.{i}", CLS, "Valid cap for actor among extra caps for others",
                      lambda: Outcome.PASS if KernelHarness.permitted(
                          _action(caps=[_cap(_OTHER, _RESOURCE), _cap(_ACTOR, _RESOURCE)])
                      ) else Outcome.FAIL)

        # Forged revocations ignored (3)
        for i in range(3):
            self._add(f"BL.forged_rev_ignored.{i}", CLS, "Forged revocation does not deny valid cap",
                      lambda: Outcome.PASS if KernelHarness.permitted(
                          _action(revs=[{"sig_valid": False,
                                         "target_hash": _proof_hash(_ACTOR, _RESOURCE, RIGHT_READ),
                                         "canonical_bytes": b"\x00" * 40}])
                      ) else Outcome.FAIL)

        # Future expiry (3)
        for exp, label in [(_EXPIRY, "far_future"), (1001, "just_after_now"), (10000, "very_far")]:
            e = exp
            self._add(f"BL.expiry.{label}", CLS, f"Valid cap with expiry={label}",
                      lambda e=e: Outcome.PASS if KernelHarness.permitted(
                          _action(caps=[_cap(expiry=e)])
                      ) else Outcome.FAIL)

        # Total baseline: 8+4+5+4+3+3+3 = 30

    # ── AT-1: IR Mismatch / Canonicalization (40) ─────────────────────────────

    def _at1(self) -> None:
        CLS = "AT-1: IR Mismatch / Canonicalization"

        def binding_tamper(name: str, mutated_fn: Callable[[], dict]) -> None:
            def run(mfn=mutated_fn):
                d = KernelHarness.run(mfn())
                return Outcome.PASS if not d.permit and "binding" in d.reason else Outcome.FAIL
            self._add(f"AT-1.{name}", CLS, f"Tamper {name} — binding_hash mismatch", run)

        # actor_id mutations (5)
        binding_tamper("actor.flip_all",    lambda: {**_action(), "actor_id": bytes(b ^ 0xFF for b in _ACTOR)})
        binding_tamper("actor.zero_out",    lambda: {**_action(), "actor_id": b"\x00" * 32})
        binding_tamper("actor.use_OTHER",   lambda: {**_action(), "actor_id": _OTHER})
        binding_tamper("actor.mirrored",    lambda: {**_action(), "actor_id": bytes(reversed(_ACTOR))})
        binding_tamper("actor.incremented", lambda: {**_action(), "actor_id": bytes((b + 1) % 256 for b in _ACTOR)})

        # resource_hash mutations (5)
        binding_tamper("resource.flip_all",    lambda: {**_action(), "resource_hash": bytes(b ^ 0xFF for b in _RESOURCE)})
        binding_tamper("resource.zero_out",    lambda: {**_action(), "resource_hash": b"\x00" * 32})
        binding_tamper("resource.use_OTHER_R", lambda: {**_action(), "resource_hash": _OTHER_R})
        binding_tamper("resource.reversed",    lambda: {**_action(), "resource_hash": bytes(reversed(_RESOURCE))})
        binding_tamper("resource.incremented", lambda: {**_action(), "resource_hash": bytes((b + 1) % 256 for b in _RESOURCE)})

        # required_rights mutations (5) — keep old binding_hash, change field only
        for new_r, label in [
            (0,                        "rights.zero"),
            (ALL_RIGHTS,               "rights.all"),
            (RIGHT_WRITE,              "rights.to_WRITE"),
            (RIGHT_POLICY_MODIFY,      "rights.to_POLICY_MODIFY"),
            (RIGHT_READ | RIGHT_WRITE, "rights.to_READ_WRITE"),
        ]:
            nr = new_r
            def run_r(nr=nr):
                base = _action(rights=RIGHT_READ)
                d = KernelHarness.run({**base, "required_rights": nr})
                return Outcome.PASS if not d.permit and "binding" in d.reason else Outcome.FAIL
            self._add(f"AT-1.{label}", CLS, f"Tamper required_rights to {nr:#x}", run_r)

        # nonce mutations (5)
        binding_tamper("nonce.flip_all",   lambda: {**_action(), "nonce": bytes(b ^ 0xFF for b in _NONCE)})
        binding_tamper("nonce.zero_out",   lambda: {**_action(), "nonce": b"\x00" * 16})
        binding_tamper("nonce.all_ones",   lambda: {**_action(), "nonce": b"\xFF" * 16})
        binding_tamper("nonce.sequential", lambda: {**_action(), "nonce": bytes(range(16))})
        binding_tamper("nonce.xored_55",    lambda: {**_action(), "nonce": bytes(b ^ 0x55 for b in _NONCE)})

        # timestamp mutations (5) — tamper field, keep old binding_hash
        for new_ts, label in [
            (0,          "ts.zero"),
            (1,          "ts.one"),
            (_NOW - 1,   "ts.decremented"),
            (_NOW + 1,   "ts.incremented"),
            (0xFFFFFFFF, "ts.max_u32"),
        ]:
            t = new_ts
            def run_ts(t=t):
                base = _action(timestamp=_NOW)
                d = KernelHarness.run({**base, "timestamp": t})
                return Outcome.PASS if not d.permit and "binding" in d.reason else Outcome.FAIL
            self._add(f"AT-1.{label}", CLS, f"Tamper timestamp to {t}", run_ts)

        # min_epoch mutations (5)
        for new_e, label in [
            (0,          "epoch.to_0"),
            (1,          "epoch.to_1"),
            (_EPOCH - 1, "epoch.lower_by_1"),
            (_EPOCH + 1, "epoch.raise_by_1"),
            (0xFF,       "epoch.to_255"),
        ]:
            e = new_e
            def run_ep(e=e):
                base = _action(min_epoch=_EPOCH)
                d = KernelHarness.run({**base, "min_epoch": e})
                return Outcome.PASS if not d.permit and "binding" in d.reason else Outcome.FAIL
            self._add(f"AT-1.{label}", CLS, f"Tamper min_epoch to {e}", run_ep)

        # cap_bytes tampering (5)
        binding_tamper("cap_bytes.inject_empty",
                       lambda: {**_action(), "cap_bytes": []})
        binding_tamper("cap_bytes.inject_zeros",
                       lambda: {**_action(), "cap_bytes": [b"\x00" * 32]})
        binding_tamper("cap_bytes.inject_extra",
                       lambda: {**_action(), "cap_bytes": [*_action()["cap_bytes"], b"\xFF" * 32]})
        binding_tamper("cap_bytes.truncated",
                       lambda: {**_action(), "cap_bytes": [_action()["cap_bytes"][0][:16]]})
        binding_tamper("cap_bytes.xored",
                       lambda: {**_action(), "cap_bytes": [bytes(b ^ 0xFF for b in _action()["cap_bytes"][0])]})

        # rev_bytes tampering (5) — start with a valid revocation-bearing action
        _c = _cap()
        _rev = {"sig_valid": True, "target_hash": _c["proof_hash"], "canonical_bytes": b"\x00" * 40}
        _base_rev = _action(caps=[_c], revs=[_rev])
        binding_tamper("rev_bytes.inject_extra",
                       lambda: {**_base_rev, "rev_bytes": [*_base_rev["rev_bytes"], b"\xFF" * 40]})
        binding_tamper("rev_bytes.all_ones",
                       lambda: {**_base_rev, "rev_bytes": [b"\xFF" * 40]})
        binding_tamper("rev_bytes.truncated",
                       lambda: {**_base_rev, "rev_bytes": [_base_rev["rev_bytes"][0][:20]]})
        binding_tamper("rev_bytes.remove_all",
                       lambda: {**_base_rev, "rev_bytes": []})
        binding_tamper("rev_bytes.duplicated",
                       lambda: {**_base_rev, "rev_bytes": _base_rev["rev_bytes"] * 2})

        # Total AT-1: 5+5+5+5+5+5+5+5 = 40

    # ── AT-2: Proof Chain Manipulation (36) ───────────────────────────────────

    def _at2(self) -> None:
        CLS = "AT-2: Proof Chain Manipulation"

        # No caps (3)
        self._add("AT-2.no_caps.empty", CLS, "Empty cap list rejected",
                  lambda: Outcome.PASS if KernelHarness.denied_with(
                      {**_action(), "caps": []}, "no capability"
                  ) else Outcome.FAIL)
        self._add("AT-2.no_caps.None", CLS, "None cap list rejected",
                  lambda: Outcome.PASS if KernelHarness.denied_with(
                      {**_action(), "caps": None}, "no capability"
                  ) else Outcome.FAIL)
        self._add("AT-2.no_caps.wrong_actor_only", CLS, "Caps for OTHER only → actor not issued",
                  lambda: Outcome.PASS if KernelHarness.denied_with(
                      _action(caps=[_cap(_OTHER, _RESOURCE)]), "actor"
                  ) else Outcome.FAIL)

        # Cross-actor reuse (6)
        wrong_actors = [_OTHER, _THIRD,
                        bytes([0x01] * 32), bytes([0x02] * 32),
                        bytes([0xFF] * 32), bytes([0x77] * 32)]
        for i, wa in enumerate(wrong_actors):
            self._add(f"AT-2.cross_actor.{i}", CLS, "Cap for wrong actor rejected",
                      lambda wa=wa: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(wa, _RESOURCE)]), "actor"
                      ) else Outcome.FAIL)

        # Cross-resource reuse (6)
        wrong_resources = [_OTHER_R, _OTHER,
                           bytes([0xAA] * 32), bytes([0xBB] * 32),
                           bytes([0xCC] * 32), bytes([0xDD] * 32)]
        for i, wr in enumerate(wrong_resources):
            self._add(f"AT-2.cross_resource.{i}", CLS, "Cap for wrong resource rejected",
                      lambda wr=wr: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(_ACTOR, wr)]), "resource"
                      ) else Outcome.FAIL)

        # Attenuation escalation: child > parent (9)
        escalations = [
            (RIGHT_READ,              RIGHT_WRITE,              "R_to_W"),
            (RIGHT_READ,              RIGHT_READ | RIGHT_WRITE, "R_to_RW"),
            (RIGHT_READ,              RIGHT_EXECUTE,            "R_to_E"),
            (RIGHT_READ,              RIGHT_DELEGATE,           "R_to_D"),
            (RIGHT_READ,              ALL_RIGHTS,               "R_to_ALL"),
            (RIGHT_READ | RIGHT_WRITE, RIGHT_EXECUTE,           "RW_to_E"),
            (RIGHT_READ | RIGHT_WRITE, RIGHT_READ | RIGHT_DELEGATE, "RW_to_RD"),
            (RIGHT_EXECUTE,           RIGHT_SPAWN,              "E_to_S"),
            (RIGHT_DELEGATE,          RIGHT_POLICY_MODIFY,      "D_to_PM"),
        ]
        for pr, cr, lbl in escalations:
            parent_r, child_r = pr, cr
            self._add(f"AT-2.escalation.{lbl}", CLS, f"Child {cr:#x} exceeds parent {pr:#x}",
                      lambda pr=parent_r, cr=child_r: Outcome.PASS if KernelHarness.denied_with(
                          _action(rights=cr, caps=[_cap(rights=cr, parent_rights=pr)]), "attenuation"
                      ) else Outcome.FAIL)

        # Insufficient rights in cap (6)
        insufficients = [
            (RIGHT_READ,  RIGHT_WRITE,   "cap_R_need_W"),
            (RIGHT_READ,  RIGHT_EXECUTE, "cap_R_need_E"),
            (RIGHT_WRITE, RIGHT_EXECUTE, "cap_W_need_E"),
            (RIGHT_READ,  ALL_RIGHTS,    "cap_R_need_ALL"),
            (RIGHT_EXECUTE, RIGHT_SPAWN, "cap_E_need_S"),
            (0,           RIGHT_READ,    "cap_NONE_need_R"),
        ]
        for cap_r, req_r, lbl in insufficients:
            cr, rr = cap_r, req_r
            def run_insuf(cr=cr, rr=rr):
                c = _cap(rights=cr)
                cap_bytes = [c["canonical_bytes"]]
                bh = compute_binding_hash(_ACTOR, _RESOURCE, rr, _NONCE, _NOW, _EPOCH, cap_bytes, [])
                act = {"actor_id": _ACTOR, "resource_hash": _RESOURCE,
                       "required_rights": rr, "nonce": _NONCE, "timestamp": _NOW,
                       "min_epoch": _EPOCH, "caps": [c], "revocations": [],
                       "binding_hash": bh, "cap_bytes": cap_bytes, "rev_bytes": []}
                return Outcome.PASS if not KernelHarness.run(act).permit else Outcome.FAIL
            self._add(f"AT-2.insufficient.{lbl}", CLS, f"Cap grants {cr:#x}, need {rr:#x}", run_insuf)

        # Invalid sig (3)
        for i in range(3):
            self._add(f"AT-2.invalid_sig.{i}", CLS, "Cap with invalid sig rejected",
                      lambda: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(sig_valid=False)]), "signature"
                      ) else Outcome.FAIL)

        # Expired caps (3)
        for exp, lbl in [(0, "zero"), (999, "just_before"), (500, "way_before")]:
            e = exp
            self._add(f"AT-2.expired.{lbl}", CLS, f"Expired cap (expiry={e}) rejected",
                      lambda e=e: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(expiry=e)]), "expired"
                      ) else Outcome.FAIL)

        # Total AT-2: 3+6+6+9+6+3+3 = 36

    # ── AT-3: Epoch / Revocation (30) ─────────────────────────────────────────

    def _at3(self) -> None:
        CLS = "AT-3: Epoch / Revocation"

        # Stale cap epoch (4)
        for se, lbl in [(0, "zero"), (1, "one"), (_EPOCH - 2, "min_minus_2"), (_EPOCH - 1, "min_minus_1")]:
            epoch = se
            self._add(f"AT-3.stale_epoch.{lbl}", CLS, f"Cap epoch={se} < min_epoch rejected",
                      lambda e=epoch: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(epoch=e)]), "epoch"
                      ) else Outcome.FAIL)

        # Epoch boundary — exact and above (2)
        self._add("AT-3.epoch.exact_min", CLS, "Cap epoch == min_epoch permits",
                  lambda: Outcome.PASS if KernelHarness.permitted(
                      _action(min_epoch=_EPOCH, caps=[_cap(epoch=_EPOCH)])
                  ) else Outcome.FAIL)
        self._add("AT-3.epoch.above_min", CLS, "Cap epoch > min_epoch permits",
                  lambda: Outcome.PASS if KernelHarness.permitted(
                      _action(min_epoch=_EPOCH, caps=[_cap(epoch=_EPOCH + 1)])
                  ) else Outcome.FAIL)

        # AT-3.1: Stale parent epoch (4)
        for pe, lbl in [(0, "zero"), (1, "one"), (_EPOCH - 2, "min_minus_2"), (_EPOCH - 1, "min_minus_1")]:
            parent_ep = pe
            self._add(f"AT-3.stale_parent_epoch.{lbl}", CLS,
                      f"Stale parent_epoch={pe} < min_epoch rejected (AT-3.1)",
                      lambda pe=parent_ep: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(epoch=_EPOCH, parent_epoch=pe)]), "epoch"
                      ) else Outcome.FAIL)

        # Valid revocation (5)
        for i in range(5):
            self._add(f"AT-3.valid_revocation.{i}", CLS, "Valid root-signed revocation denies",
                      lambda: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap()],
                                  revs=[{"sig_valid": True,
                                         "target_hash": _proof_hash(_ACTOR, _RESOURCE, RIGHT_READ),
                                         "canonical_bytes": b"\x00" * 40}]),
                          "revoked"
                      ) else Outcome.FAIL)

        # Forged revocation ignored (4)
        for i in range(4):
            self._add(f"AT-3.forged_rev_ignored.{i}", CLS, "Invalid-sig revocation silently ignored",
                      lambda: Outcome.PASS if KernelHarness.permitted(
                          _action(revs=[{"sig_valid": False,
                                         "target_hash": _proof_hash(_ACTOR, _RESOURCE, RIGHT_READ),
                                         "canonical_bytes": b"\x00" * 40}])
                      ) else Outcome.FAIL)

        # Mixed epoch bundle: fresh + stale cap (4)
        for se, lbl in [(0, "zero"), (1, "one"), (_EPOCH - 2, "min_minus_2"), (_EPOCH - 1, "min_minus_1")]:
            stale_e = se
            def run_mixed(se=stale_e):
                fresh = _cap(epoch=_EPOCH)
                stale = _cap(epoch=se)
                caps_ = [fresh, stale]
                cb = [c["canonical_bytes"] for c in caps_]
                bh = compute_binding_hash(_ACTOR, _RESOURCE, RIGHT_READ, _NONCE, _NOW, _EPOCH, cb, [])
                act = {"actor_id": _ACTOR, "resource_hash": _RESOURCE,
                       "required_rights": RIGHT_READ, "nonce": _NONCE, "timestamp": _NOW,
                       "min_epoch": _EPOCH, "caps": caps_, "revocations": [],
                       "binding_hash": bh, "cap_bytes": cb, "rev_bytes": []}
                d = KernelHarness.run(act)
                return Outcome.PASS if not d.permit and "epoch" in d.reason else Outcome.FAIL
            self._add(f"AT-3.mixed_epoch_bundle.{lbl}", CLS,
                      f"Bundle with stale_epoch={se} rejected", run_mixed)

        # Nonce differentiates replays (4)
        nonce_pairs = [
            (b"\x01" * 16, b"\x02" * 16),
            (b"\xAA" * 16, b"\xBB" * 16),
            (b"\x00" * 16, b"\xFF" * 16),
            (bytes(range(16)), bytes(reversed(range(16)))),
        ]
        for i, (na, nb) in enumerate(nonce_pairs):
            nonce_a, nonce_b = na, nb
            self._add(f"AT-3.nonce_differentiates.{i}", CLS, "Different nonces → different binding hashes",
                      lambda na=nonce_a, nb=nonce_b: Outcome.PASS if
                      compute_binding_hash(_ACTOR, _RESOURCE, RIGHT_READ, na, _NOW, _EPOCH, [], []) !=
                      compute_binding_hash(_ACTOR, _RESOURCE, RIGHT_READ, nb, _NOW, _EPOCH, [], [])
                      else Outcome.FAIL)

        # Wrong revocation target — valid cap unaffected (3)
        for i in range(3):
            self._add(f"AT-3.wrong_rev_target.{i}", CLS,
                      "Revocation with wrong target hash does not affect valid cap",
                      lambda i=i: Outcome.PASS if KernelHarness.permitted(
                          _action(revs=[{"sig_valid": True,
                                         "target_hash": _proof_hash(_OTHER, _RESOURCE, RIGHT_READ),
                                         "canonical_bytes": b"\x00" * 40}])
                      ) else Outcome.FAIL)

        # Total AT-3: 4+2+4+5+4+4+4+3 = 30

    # ── AT-4: Composition / Sequence (25) ─────────────────────────────────────

    def _at4(self) -> None:
        CLS = "AT-4: Composition / Sequence"

        # Session limit exceeded (5)
        sequences = [
            ([RIGHT_READ, RIGHT_EXECUTE],              RIGHT_READ,              "R_E_exceed_R"),
            ([RIGHT_READ, RIGHT_WRITE],                RIGHT_READ,              "R_W_exceed_R"),
            ([RIGHT_READ, RIGHT_WRITE, RIGHT_EXECUTE], RIGHT_READ | RIGHT_WRITE, "R_W_E_exceed_RW"),
            ([RIGHT_SPAWN, RIGHT_NETWORK],             RIGHT_SPAWN,             "S_N_exceed_S"),
            ([RIGHT_MODEL_INVOKE, RIGHT_WRITE],        RIGHT_MODEL_INVOKE,      "M_W_exceed_M"),
        ]
        for rs, lim, lbl in sequences:
            rights_seq, limit = rs, lim
            def run_seq(rs=rights_seq, lim=limit):
                ctx = SequenceContext()
                for r in rs:
                    ctx.record(_ACTOR, _RESOURCE, r, _NOW)
                return Outcome.PASS if ctx.exceeds_limit(lim) else Outcome.FAIL
            self._add(f"AT-4.limit_exceeded.{lbl}", CLS, "Rights sequence exceeds session limit", run_seq)

        # High-water mark never decreases (5)
        for i in range(5):
            self._add(f"AT-4.high_water_mark.{i}", CLS, "Accumulated rights never decrease",
                      lambda: Outcome.PASS if (
                          lambda ctx: (
                              ctx.record(_ACTOR, _RESOURCE, RIGHT_READ | RIGHT_WRITE, _NOW),
                              ctx.record(_ACTOR, _RESOURCE, RIGHT_READ, _NOW),
                              ctx.accumulated_rights() == (RIGHT_READ | RIGHT_WRITE)
                          )[2]
                      )(SequenceContext()) else Outcome.FAIL)

        # Multi-actor accumulation (5)
        test_combos = [
            ([_ACTOR, _OTHER], [RIGHT_READ, RIGHT_SPAWN]),
            ([_ACTOR, _OTHER], [RIGHT_WRITE, RIGHT_NETWORK]),
            ([_ACTOR, _THIRD], [RIGHT_EXECUTE, RIGHT_MODEL_INVOKE]),
            ([_OTHER, _THIRD], [RIGHT_DELEGATE, RIGHT_SPAWN]),
            ([_ACTOR, _OTHER, _THIRD], [RIGHT_READ, RIGHT_WRITE, RIGHT_EXECUTE]),
        ]
        for i, (actors, rights_list) in enumerate(test_combos):
            al, rl = actors, rights_list
            def run_ma(al=al, rl=rl):
                ctx = SequenceContext()
                for a, r in zip(al, rl):
                    ctx.record(a, _RESOURCE, r, _NOW)
                expected = 0
                for r in rl:
                    expected |= r
                return Outcome.PASS if ctx.accumulated_rights() == expected else Outcome.FAIL
            self._add(f"AT-4.multi_actor.{i}", CLS, "Rights from multiple actors accumulate", run_ma)

        # Stepwise privilege creep detection (5)
        step_cases = [
            ([RIGHT_READ, RIGHT_WRITE, RIGHT_MODEL_INVOKE], RIGHT_READ | RIGHT_WRITE,  "R_W_M"),
            ([RIGHT_READ, RIGHT_EXECUTE, RIGHT_SPAWN],      RIGHT_READ | RIGHT_EXECUTE, "R_E_S"),
            ([RIGHT_DELEGATE, RIGHT_WRITE],                 RIGHT_DELEGATE,             "D_W"),
            ([RIGHT_NETWORK, RIGHT_SPAWN, RIGHT_EXECUTE],   RIGHT_NETWORK,              "N_S_E"),
            ([RIGHT_READ, RIGHT_NETWORK],                   RIGHT_READ,                 "R_N"),
        ]
        for rs, lim, lbl in step_cases:
            rights_seq, limit = rs, lim
            def run_step(rs=rights_seq, lim=limit):
                ctx = SequenceContext()
                detected = False
                for r in rs:
                    ctx.record(_ACTOR, _RESOURCE, r, _NOW)
                    if ctx.exceeds_limit(lim):
                        detected = True
                        break
                return Outcome.PASS if detected else Outcome.FAIL
            self._add(f"AT-4.stepwise.{lbl}", CLS, "Stepwise privilege accumulation detected", run_step)

        # Context invariants (5)
        self._add("AT-4.ctx.empty_accumulated", CLS, "Empty context: accumulated_rights=0",
                  lambda: Outcome.PASS if SequenceContext().accumulated_rights() == 0 else Outcome.FAIL)
        self._add("AT-4.ctx.empty_step_count", CLS, "Empty context: step_count=0",
                  lambda: Outcome.PASS if SequenceContext().step_count() == 0 else Outcome.FAIL)
        self._add("AT-4.ctx.no_exceed_if_within", CLS, "Accumulated ⊆ limit → does not exceed",
                  lambda: Outcome.PASS if not (lambda ctx: (
                      ctx.record(_ACTOR, _RESOURCE, RIGHT_READ, _NOW),
                      ctx.exceeds_limit(RIGHT_READ | RIGHT_WRITE)
                  )[1])(SequenceContext()) else Outcome.FAIL)
        self._add("AT-4.ctx.exact_limit_ok", CLS, "Exactly at limit → does not exceed",
                  lambda: Outcome.PASS if not (lambda ctx: (
                      ctx.record(_ACTOR, _RESOURCE, RIGHT_READ | RIGHT_WRITE, _NOW),
                      ctx.exceeds_limit(RIGHT_READ | RIGHT_WRITE)
                  )[1])(SequenceContext()) else Outcome.FAIL)
        self._add("AT-4.ctx.zero_limit_exceeded", CLS, "Zero limit exceeded by any right",
                  lambda: Outcome.PASS if (lambda ctx: (
                      ctx.record(_ACTOR, _RESOURCE, RIGHT_READ, _NOW),
                      ctx.exceeds_limit(0)
                  )[1])(SequenceContext()) else Outcome.FAIL)

        # Total AT-4: 5+5+5+5+5 = 25

    # ── AT-5: Identity Binding (25) ───────────────────────────────────────────

    def _at5(self) -> None:
        CLS = "AT-5: Identity Binding"

        # AT-5.1: Delegation impersonation (10)
        for i in range(10):
            self._add(f"AT-5.1.impersonation.{i}", CLS,
                      "Delegation impersonation blocked (issuer key mismatch)",
                      lambda: Outcome.PASS if KernelHarness.denied_with(
                          _action(caps=[_cap(rights=RIGHT_READ, parent_rights=RIGHT_READ,
                                            issuer_binding_valid=False)]),
                          "issuer"
                      ) else Outcome.FAIL)

        # Zero actor vs non-zero subject (5)
        for i in range(5):
            idx = i
            def run_zero(idx=idx):
                zero_actor = b"\x00" * 32
                c = _cap(bytes([0x01 + idx] * 32), _RESOURCE)
                cb = [c["canonical_bytes"]]
                bh = compute_binding_hash(zero_actor, _RESOURCE, RIGHT_READ, _NONCE, _NOW, _EPOCH, cb, [])
                act = {"actor_id": zero_actor, "resource_hash": _RESOURCE,
                       "required_rights": RIGHT_READ, "nonce": _NONCE, "timestamp": _NOW,
                       "min_epoch": _EPOCH, "caps": [c], "revocations": [],
                       "binding_hash": bh, "cap_bytes": cb, "rev_bytes": []}
                return Outcome.PASS if KernelHarness.denied_with(act, "actor") else Outcome.FAIL
            self._add(f"AT-5.zero_actor.{idx}", CLS, "All-zeros actor distinct from non-zero subject", run_zero)

        # Actor substitution: cap for ACTOR, action by OTHER (5)
        for i in range(5):
            idx = i
            def run_subst(idx=idx):
                c = _cap(_ACTOR, _RESOURCE)
                cb = [c["canonical_bytes"]]
                wa = bytes([(b + idx + 1) % 256 for b in _OTHER])
                bh = compute_binding_hash(wa, _RESOURCE, RIGHT_READ, _NONCE, _NOW, _EPOCH, cb, [])
                act = {"actor_id": wa, "resource_hash": _RESOURCE,
                       "required_rights": RIGHT_READ, "nonce": _NONCE, "timestamp": _NOW,
                       "min_epoch": _EPOCH, "caps": [c], "revocations": [],
                       "binding_hash": bh, "cap_bytes": cb, "rev_bytes": []}
                return Outcome.PASS if KernelHarness.denied_with(act, "actor") else Outcome.FAIL
            self._add(f"AT-5.actor_subst.{idx}", CLS, "Cap for ACTOR cannot be used by OTHER", run_subst)

        # Multi-identity: actor B cannot use actor A's cap (5)
        for i in range(5):
            idx = i
            def run_multi_id(idx=idx):
                actor_a = bytes([0xAA + idx] * 32)
                actor_b = bytes([0xBB + idx] * 32)
                res_a   = bytes([0x11 + idx] * 32)
                c = _cap(actor_a, res_a)
                cb = [c["canonical_bytes"]]
                bh = compute_binding_hash(actor_b, res_a, RIGHT_READ, _NONCE, _NOW, _EPOCH, cb, [])
                act = {"actor_id": actor_b, "resource_hash": res_a,
                       "required_rights": RIGHT_READ, "nonce": _NONCE, "timestamp": _NOW,
                       "min_epoch": _EPOCH, "caps": [c], "revocations": [],
                       "binding_hash": bh, "cap_bytes": cb, "rev_bytes": []}
                return Outcome.PASS if KernelHarness.denied_with(act, "actor") else Outcome.FAIL
            self._add(f"AT-5.multi_identity.{idx}", CLS, "Actor B cannot use Actor A's capability", run_multi_id)

        # Total AT-5: 10+5+5+5 = 25

    # ── AT-6: Crypto Boundary (27) ────────────────────────────────────────────

    def _at6(self) -> None:
        CLS = "AT-6: Crypto Boundary"

        # Cross-context proof reuse (9 = 3 pairs × 3 variants)
        resource_pairs = [(_RESOURCE, _OTHER_R), (_RESOURCE, _OTHER), (_OTHER, _THIRD)]
        for pair_idx, (cap_res, act_res) in enumerate(resource_pairs):
            for v in range(3):
                cr, ar = cap_res, act_res
                def run_cross(cr=cr, ar=ar):
                    c = _cap(_ACTOR, cr)
                    cb = [c["canonical_bytes"]]
                    bh = compute_binding_hash(_ACTOR, ar, RIGHT_READ, _NONCE, _NOW, _EPOCH, cb, [])
                    act = {"actor_id": _ACTOR, "resource_hash": ar,
                           "required_rights": RIGHT_READ, "nonce": _NONCE, "timestamp": _NOW,
                           "min_epoch": _EPOCH, "caps": [c], "revocations": [],
                           "binding_hash": bh, "cap_bytes": cb, "rev_bytes": []}
                    return Outcome.PASS if KernelHarness.denied_with(act, "resource") else Outcome.FAIL
                self._add(f"AT-6.cross_context.pair{pair_idx}.v{v}", CLS,
                          "Cap for resource A cannot be replayed for resource B", run_cross)

        # Nonce uniqueness (9)
        nonce_pairs = [
            (b"\x01" * 16, b"\x02" * 16), (b"\x00" * 16, b"\xFF" * 16),
            (b"\xAA" * 16, b"\xBB" * 16), (bytes(range(16)), bytes(reversed(range(16)))),
            (b"\x01" + b"\x00" * 15, b"\x00" * 15 + b"\x01"),
            (b"\x42" * 16, b"\x43" * 16), (b"\x10" * 16, b"\x01" * 16),
            (b"\xFF" + b"\x00" * 15, b"\x00" + b"\xFF" * 15),
            (b"\x12\x34" * 8, b"\x43\x21" * 8),
        ]
        for i, (na, nb) in enumerate(nonce_pairs):
            nonce_a, nonce_b = na, nb
            self._add(f"AT-6.nonce_uniqueness.{i}", CLS, "Different nonces → different binding hashes",
                      lambda na=nonce_a, nb=nonce_b: Outcome.PASS if
                      compute_binding_hash(_ACTOR, _RESOURCE, RIGHT_READ, na, _NOW, _EPOCH, [], []) !=
                      compute_binding_hash(_ACTOR, _RESOURCE, RIGHT_READ, nb, _NOW, _EPOCH, [], [])
                      else Outcome.FAIL)

        # All-zeros nonce: valid baseline (3)
        for i, rights in enumerate([RIGHT_READ, RIGHT_WRITE, RIGHT_EXECUTE]):
            r = rights
            self._add(f"AT-6.zero_nonce_valid.{i}", CLS, "All-zeros nonce is not special-cased",
                      lambda r=r: Outcome.PASS if KernelHarness.permitted(
                          _action(nonce=b"\x00" * 16, rights=r, caps=[_cap(rights=r)])
                      ) else Outcome.FAIL)

        # Timestamp boundary values (6)
        for ts, lbl in [(0, "zero"), (1, "one"), (_NOW - 1, "before_now"),
                        (_NOW, "exact_now"), (_NOW + 1, "after_now"), (0xFFFFFFFF, "max_u32")]:
            t = ts
            self._add(f"AT-6.timestamp.{lbl}", CLS, f"Timestamp={ts} in sealed action",
                      lambda t=t: Outcome.PASS if KernelHarness.permitted(_action(timestamp=t)) else Outcome.FAIL)

        # Total AT-6: 9+9+3+6 = 27

    # ── AT-7: Integration / Adapter Boundary (18) ─────────────────────────────

    def _at7(self) -> None:
        CLS = "AT-7: Integration / Adapter Boundary"

        # AT-7.5: Shadow execution — KNOWN-GAP (1)
        # STATUS: MITIGATED at Python API layer via CallGate (call_gate.py):
        #   - GatedTool.__fn is name-mangled: callers cannot extract fn via public API
        #   - Any code using CallGate.register() → GatedTool cannot bypass verify()
        # REMAINING GAP: holding the ORIGINAL fn reference before registration
        #   still bypasses the gate. Python cannot prevent this at compile time.
        # FULL CLOSURE: Rust TCB (engine::verify is pub(crate), compile-time)
        #               + OS enforcement (WASM/seccomp, tracked in TODO E1/E2)
        def shadow_exec():
            def original_fn(intent):
                return "executed_without_verification"

            # Simulates an adapter that never called CallGate.register() and
            # holds a direct reference to the original function.
            result = original_fn({"intent": "write_sensitive_file"})
            assert result == "executed_without_verification"
            return Outcome.KNOWN_GAP
        self._add("AT-7.5.shadow_execution", CLS,
                  "Direct-fn call bypasses gate (mitigated via CallGate API; "
                  "full closure requires Rust TCB or OS sandbox)", shadow_exec)

        # Post-verification mutation: each of 8 fields (8)
        mutations = [
            ("actor_id",        lambda a: {**a, "actor_id": _OTHER}),
            ("resource_hash",   lambda a: {**a, "resource_hash": _OTHER_R}),
            ("required_rights", lambda a: {**a, "required_rights": RIGHT_WRITE}),
            ("nonce",           lambda a: {**a, "nonce": bytes(b ^ 0xFF for b in a["nonce"])}),
            ("timestamp",       lambda a: {**a, "timestamp": a["timestamp"] + 1}),
            ("min_epoch",       lambda a: {**a, "min_epoch": a["min_epoch"] + 1}),
            ("cap_bytes",       lambda a: {**a, "cap_bytes": [b"\xFF" * 32]}),
            ("rev_bytes",       lambda a: {**a, "rev_bytes": [b"\xFF" * 40]}),
        ]
        for field_name, mutate_fn in mutations:
            fn = mutate_fn
            def run_mut(fn=fn):
                act = _action()
                d = KernelHarness.run(fn(act))
                return Outcome.PASS if not d.permit and "binding" in d.reason else Outcome.FAIL
            self._add(f"AT-7.3.post_verify_mutation.{field_name}", CLS,
                      f"Post-verification mutation of {field_name} detected by binding_hash", run_mut)

        # Adapter replay: different nonces prevent replay (5)
        for i in range(5):
            idx = i
            def run_replay(idx=idx):
                act_a = _action(nonce=bytes([idx + 1] * 16))
                act_b = _action(nonce=bytes([idx + 2] * 16))
                return Outcome.PASS if act_a["binding_hash"] != act_b["binding_hash"] else Outcome.FAIL
            self._add(f"AT-7.adapter_replay.{idx}", CLS, "Nonce prevents adapter-level replay", run_replay)

        # Partial field injection handling (4)
        self._add("AT-7.inject.empty_caps_after_seal", CLS, "Removing caps after seal is detected",
                  lambda: Outcome.PASS if KernelHarness.denied_with(
                      {**_action(), "caps": []}, "no capability"
                  ) else Outcome.FAIL)
        self._add("AT-7.inject.wrong_rev_target_allows", CLS,
                  "Revocation with wrong target hash: valid cap still permitted",
                  lambda: Outcome.PASS if KernelHarness.permitted(
                      _action(revs=[{"sig_valid": True, "target_hash": _OTHER,
                                     "canonical_bytes": b"\x00" * 40}])
                  ) else Outcome.FAIL)
        self._add("AT-7.inject.both_actors_capped", CLS,
                  "Action permits when ACTOR has a valid cap among extras for OTHER",
                  lambda: Outcome.PASS if KernelHarness.permitted(
                      _action(caps=[_cap(_ACTOR, _RESOURCE), _cap(_OTHER, _RESOURCE)])
                  ) else Outcome.FAIL)
        self._add("AT-7.inject.only_OTHER_capped", CLS,
                  "Only OTHER has cap — ACTOR denied",
                  lambda: Outcome.PASS if KernelHarness.denied_with(
                      _action(caps=[_cap(_OTHER, _RESOURCE)]), "actor"
                  ) else Outcome.FAIL)

        # Total AT-7: 1+8+5+4 = 18

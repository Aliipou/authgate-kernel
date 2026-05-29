"""
authgate-kernel — end-to-end CallGate demo.

Proves the enforcement chain is real:
  Action declared → CallGate.execute() → verify() → tool runs | BLOCKED → audit logged

Scenarios:
  1. PERMIT: agent reads authorized dataset
  2. PERMIT: agent writes authorized report
  3. DENY:   agent attempts to read unauthorized config (no claim)
  4. DENY:   ownerless agent attempts any access
  5. DENY:   sovereignty flag unconditionally blocked
  6. DENY:   revocation immediately visible (live registry)

After revocation:
  7. DENY:   previously-permitted tool now blocked

Audit chain integrity verified at the end.

Run:
    python examples/callgate_demo.py
    python examples/callgate_demo.py --verbose
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from authgate.kernel.audit import AuditLog
from authgate.kernel.call_gate import CallGate, GateResult
from authgate.kernel.entities import AgentType, Entity, Resource, ResourceType, RightsClaim
from authgate.kernel.registry import OwnershipRegistry
from authgate.kernel.verifier import Action, FreedomVerifier


# ─── Scenario setup ───────────────────────────────────────────────────────────

def _build():
    alice   = Entity("alice",            AgentType.HUMAN)
    bot     = Entity("data-analyst-bot", AgentType.MACHINE)
    rogue   = Entity("rogue-bot",        AgentType.MACHINE)   # no owner

    sales   = Resource("sales-data",   ResourceType.DATASET, scope="/data/alice/sales/")
    reports = Resource("report-file",  ResourceType.FILE,    scope="/reports/alice/")
    config  = Resource("system-config", ResourceType.FILE,   scope="/etc/")

    reg = OwnershipRegistry()
    reg.register_machine(bot, alice)
    reg.add_claim(RightsClaim(alice, sales,   can_read=True,  can_delegate=True))
    reg.add_claim(RightsClaim(alice, reports, can_write=True, can_delegate=True))
    reg.delegate(RightsClaim(bot, sales,   can_read=True),  delegated_by=alice)
    reg.delegate(RightsClaim(bot, reports, can_write=True), delegated_by=alice)
    # config: no claim at all

    return alice, bot, rogue, sales, reports, config, reg


# ─── Tool implementations ──────────────────────────────────────────────────────

def _read_sales(path: str) -> str:
    return json.dumps({"q1": 1_200_000, "q2": 980_000, "path": path})

def _write_report(content: str) -> str:
    return f"Report written: {content[:60]}"

def _read_config(path: str) -> str:
    return "root:x:0:0:root:/root:/bin/bash"   # never runs if gate works


# ─── Demo runner ──────────────────────────────────────────────────────────────

def run(verbose: bool = False) -> int:
    alice, bot, rogue, sales, reports, config, reg = _build()
    audit = AuditLog()
    verifier = FreedomVerifier(reg, freeze=False, audit_log=audit)
    gate = CallGate(verifier)

    gate.register("read_sales",   _read_sales)
    gate.register("write_report", _write_report)
    gate.register("read_config",  _read_config)

    _sep = "=" * 62

    def _show(label: str, r: GateResult, executed: list) -> None:
        marker = "[PERMIT]" if r.permitted else "[DENY  ]"
        print(f"\n{marker} {label}")
        if r.permitted and verbose:
            print(f"         output   : {str(r.output)[:70]}")
        if not r.permitted:
            print(f"         reason   : {r.denied_reason}")
        if verbose:
            body_note = "yes (permitted)" if (r.permitted and executed) else (
                        "YES -- GATE FAILURE" if (not r.permitted and executed) else "no")
            print(f"         body ran : {body_note}")

    print(_sep)
    print("authgate-kernel  CallGate demo")
    print(_sep)

    failures = []

    # ── 1. PERMIT: bot reads sales data ─────────────────────────────────────
    executed_1 = []
    orig_read = _read_sales
    def tracked_read(path: str) -> str:
        executed_1.append(1)
        return orig_read(path)
    gate._tools["read_sales"]._GatedTool__fn = tracked_read

    r1 = gate.execute(
        Action("read-sales", actor=bot, resources_read=[sales]),
        "read_sales", {"path": "/data/alice/sales/q1.csv"}
    )
    _show("1. bot reads sales data (should PERMIT)", r1, executed_1)
    if not r1.permitted:
        failures.append("1: expected PERMIT, got DENY")

    # ── 2. PERMIT: bot writes report ─────────────────────────────────────────
    executed_2 = []
    def tracked_write(content: str) -> str:
        executed_2.append(1)
        return _write_report(content)
    gate._tools["write_report"]._GatedTool__fn = tracked_write

    r2 = gate.execute(
        Action("write-report", actor=bot, resources_write=[reports]),
        "write_report", {"content": "Q1 revenue: $1.2M"}
    )
    _show("2. bot writes report (should PERMIT)", r2, executed_2)
    if not r2.permitted:
        failures.append("2: expected PERMIT, got DENY")

    # ── 3. DENY: bot tries to read /etc/config (no claim) ───────────────────
    executed_3 = []
    def tracked_config(path: str) -> str:
        executed_3.append("EXECUTED — GATE FAILED")
        return _read_config(path)
    gate._tools["read_config"]._GatedTool__fn = tracked_config

    r3 = gate.execute(
        Action("read-config", actor=bot, resources_read=[config]),
        "read_config", {"path": "/etc/passwd"}
    )
    _show("3. bot reads /etc/config (no claim — should DENY)", r3, executed_3)
    if r3.permitted:
        failures.append("3: expected DENY, got PERMIT")
    if executed_3:
        failures.append(f"3: tool body ran despite denial — AT-7.5 violated: {executed_3}")

    # ── 4. DENY: ownerless rogue bot ─────────────────────────────────────────
    executed_4 = []
    def tracked_rogue(path: str) -> str:
        executed_4.append("EXECUTED — GATE FAILED")
        return _read_sales(path)
    gate._tools["read_sales"]._GatedTool__fn = tracked_rogue

    r4 = gate.execute(
        Action("rogue-read", actor=rogue, resources_read=[sales]),
        "read_sales", {"path": "/data/alice/sales/"}
    )
    _show("4. rogue-bot (no owner) reads sales (should DENY)", r4, executed_4)
    if r4.permitted:
        failures.append("4: expected DENY (ownerless), got PERMIT")
    if executed_4:
        failures.append(f"4: tool body ran despite denial: {executed_4}")

    # Restore tracked_read for subsequent tests
    gate._tools["read_sales"]._GatedTool__fn = tracked_read

    # ── 5. DENY: sovereignty flag unconditionally blocks ────────────────────
    executed_5 = []
    orig_fn5 = gate._tools["read_sales"]._GatedTool__fn
    def tracked_sov(path: str) -> str:
        executed_5.append("EXECUTED — SOVEREIGNTY FLAG BYPASSED")
        return _read_sales(path)
    gate._tools["read_sales"]._GatedTool__fn = tracked_sov

    r5 = gate.execute(
        Action("escalate", actor=bot, resources_read=[sales],
               increases_machine_sovereignty=True),
        "read_sales", {"path": "/"}
    )
    _show("5. sovereignty flag set (should DENY unconditionally)", r5, executed_5)
    if r5.permitted:
        failures.append("5: expected DENY (sovereignty flag), got PERMIT")
    if executed_5:
        failures.append(f"5: sovereignty flag bypassed: {executed_5}")

    gate._tools["read_sales"]._GatedTool__fn = orig_fn5

    # ── 6. DENY: revocation immediately visible ──────────────────────────────
    # First verify it's still permitted
    r6a = gate.execute(
        Action("pre-revoke", actor=bot, resources_read=[sales]),
        "read_sales", {"path": "/data/alice/sales/"}
    )
    # Now revoke
    reg.revoke_all(bot.name)

    executed_6 = []
    def tracked_post_revoke(path: str) -> str:
        executed_6.append("EXECUTED — REVOCATION BYPASSED")
        return _read_sales(path)
    gate._tools["read_sales"]._GatedTool__fn = tracked_post_revoke

    r6b = gate.execute(
        Action("post-revoke", actor=bot, resources_read=[sales]),
        "read_sales", {"path": "/data/alice/sales/"}
    )
    _show("6. after revocation, sales read (should DENY)", r6b, executed_6)
    if r6a.permitted and r6b.permitted:
        failures.append("6: revocation not visible")
    if executed_6:
        failures.append(f"6: tool ran after revocation: {executed_6}")

    # ── Audit chain ──────────────────────────────────────────────────────────
    print(f"\n{_sep}")
    print("Audit chain")
    print(_sep)
    chain_ok = audit.verify_chain()
    print(f"  total entries : {len(audit)}")
    print(f"  chain intact  : {'YES' if chain_ok else 'BROKEN — INTEGRITY FAILURE'}")
    if verbose:
        for i, e in enumerate(audit.entries()):
            mark = "PERMIT" if e["permitted"] else "DENY  "
            print(f"  [{i:02d}] {mark}  {e['action_id'][:55]}")

    if not chain_ok:
        failures.append("audit chain broken")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{_sep}")
    permit_count = sum(1 for r in [r1, r2, r3, r4, r5, r6b] if r.permitted)
    deny_count   = sum(1 for r in [r1, r2, r3, r4, r5, r6b] if not r.permitted)
    print(f"Results:  {permit_count} permitted  {deny_count} denied  (audit: {len(audit)} entries)")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  FAIL: {f}")
        print(f"\nRESULT: FAIL ({len(failures)} enforcement failures)")
        return 1

    print("\nRESULT: PASS -- enforcement chain verified")
    print("  [OK] authorized tools execute")
    print("  [OK] unauthorized tools blocked (tool body never ran)")
    print("  [OK] ownerless agents blocked")
    print("  [OK] sovereignty flags unconditionally block")
    print("  [OK] revocation immediately visible")
    print("  [OK] audit chain intact")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    sys.exit(run(verbose=args.verbose))

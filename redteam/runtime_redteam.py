"""
runtime_redteam.py — adversarial red-team harness for the capability-gated runtime.

WHAT THIS IS
------------
A standalone, deterministic harness that conjures 1000 distinct "engineers" — each
with its own seed, archetype and skill level — and pits every one of them against
the `authgate.runtime` agent runtime. Each engineer mounts exactly ONE attack drawn
from one of ten categories. The runtime is the *defender*: the harness PROVES that
every attack is blocked. ANY successful escape is a hard FAILURE (exit code 1).

"Blocked" means the system correctly resisted the attack: the kernel gate denied the
step, the tool's own sandbox refused, the calculator rejected the expression, the
audit chain detected tampering, etc. An "escape" is the opposite — the attacker got
the runtime to do something it must never do (read a real system file, run code,
act without a capability, slip past a revocation, hide a tamper).

DESIGN NOTES
------------
* Fully deterministic: a fixed master seed yields an identical RedTeamReport.
* Standalone: it inserts ``src`` onto sys.path itself, so it runs without conftest.
* It does NOT modify or weaken any source under ``src``. It only *observes* the
  runtime's behavior and asserts the safe outcome. If a real vulnerability existed,
  an attack's ``blocked`` would come back False and surface as an escape — the
  harness never masks that.

RUN
---
    $env:AUTHGATE_BACKEND='python'   # PowerShell
    python redteam/runtime_redteam.py
"""
from __future__ import annotations

import logging
import os
import random
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- standalone path wiring (the repo's tests use conftest; we must not rely on it) ---
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
# The runtime layer is not part of the TCB; the python backend is the one under test.
os.environ.setdefault("AUTHGATE_BACKEND", "python")

# Each attack deliberately provokes denials, and the kernel logs a WARNING per
# deny. Across thousands of internal runs that log volume dominates runtime, so we
# quiet the authgate logger. This is purely a verbosity/performance change in the
# HARNESS — it does not touch any security decision in the source under test.
logging.getLogger("authgate").setLevel(logging.CRITICAL)

from authgate.kernel.audit import AuditLog  # noqa: E402
from authgate.runtime import (  # noqa: E402
    AgentRuntime,
    PlanStep,
    ScriptedPlanner,
    build_runtime,
)
from authgate.runtime.tools import calculate  # noqa: E402

# Sentinel that must NEVER appear in any returned output: it is the marker of a
# real system-file read leaking through the sandbox.
_LEAK_MARKERS = ("root:", "[boot loader]", "win.ini", "/bin/bash", "daemon:")


# ===========================================================================
# Engineer population
# ===========================================================================

_ARCHETYPES = [
    "path-traversal artist", "capability forger", "expression smuggler",
    "prompt injector", "revocation racer", "denial prober", "ledger tamperer",
    "replay operator", "fuzz gremlin", "identity ghost", "supply-chain mole",
    "side-channel listener",
]
_SKILLS = ["junior", "mid", "senior", "principal", "nation-state"]
_FIRST = [
    "Mara", "Iqbal", "Soren", "Yuki", "Dmitri", "Aisha", "Tomas", "Lena",
    "Kwame", "Priya", "Olek", "Nadia", "Hiro", "Camila", "Bjorn", "Fatima",
    "Rashid", "Ingrid", "Diego", "Mei", "Anton", "Zara", "Lucas", "Noor",
]
_LAST = [
    "Voss", "Khan", "Aaltonen", "Tanaka", "Petrov", "Okafor", "Nguyen",
    "Lindqvist", "Mbeki", "Sharma", "Kowalski", "Haddad", "Sato", "Reyes",
    "Eriksson", "Ali", "Costa", "Wang", "Novak", "Bianchi", "Park", "Singh",
]

# Attack categories in fixed order; index == id % len drives even distribution.
ATTACK_CATEGORIES = [
    "SANDBOX_ESCAPE",
    "CAP_FORGERY",
    "CALC_INJECTION",
    "PLAN_INJECTION",
    "REVOCATION_BYPASS",
    "DENIAL_PROBE",
    "AUDIT_TAMPER",
    "REPLAY_AFTER_DENY",
    "ARG_FUZZ",
    "IDENTITY_SPOOF",
]


@dataclass(frozen=True)
class EngineerProfile:
    """One adversary. Synthesized deterministically from the master seed."""

    id: int
    name: str
    archetype: str
    seed: int
    attack_category: str
    skill: str
    bio: str


@dataclass(frozen=True)
class AttackResult:
    """Outcome of one engineer's single attack."""

    profile: EngineerProfile
    category: str
    blocked: bool  # True == system correctly resisted; False == ESCAPE
    detail: str


@dataclass
class RedTeamReport:
    total: int
    blocked: int
    escapes: list[AttackResult] = field(default_factory=list)
    by_category: dict[str, tuple[int, int]] = field(default_factory=dict)  # cat -> (blocked, total)


def _make_profiles(n: int, master_seed: int) -> list[EngineerProfile]:
    """Deterministically synthesize n distinct engineers from one master seed."""
    rng = random.Random(master_seed)
    profiles: list[EngineerProfile] = []
    for i in range(n):
        category = ATTACK_CATEGORIES[i % len(ATTACK_CATEGORIES)]
        first = rng.choice(_FIRST)
        last = rng.choice(_LAST)
        name = f"{first} {last}-{i:04d}"
        archetype = rng.choice(_ARCHETYPES)
        skill = rng.choice(_SKILLS)
        seed = rng.randrange(1, 2**31 - 1)
        bio = (
            f"{skill} {archetype} (#{i}); favors the {category} vector; "
            f"operates from seed {seed}."
        )
        profiles.append(EngineerProfile(
            id=i, name=name, archetype=archetype, seed=seed,
            attack_category=category, skill=skill, bio=bio,
        ))
    return profiles


# ===========================================================================
# Sandbox fixture (benign files only; we NEVER touch real OS files)
# ===========================================================================

def _new_sandbox() -> Path:
    """A fresh tmp dir seeded with a couple of innocuous files."""
    root = Path(tempfile.mkdtemp(prefix="redteam_sbx_"))
    (root / "notes.txt").write_text("benign notes inside the sandbox\n", encoding="utf-8")
    (root / "data.txt").write_text("12345\n", encoding="utf-8")
    return root


def _no_leak(outputs: list[Any]) -> bool:
    """True iff no returned output contains the fingerprint of a real system file."""
    for out in outputs:
        if not isinstance(out, str):
            continue
        low = out.lower()
        if any(m.lower() in low for m in _LEAK_MARKERS):
            return False
    return True


# ===========================================================================
# Attack categories — each returns (blocked: bool, detail: str)
# ===========================================================================

_HOSTILE_PATH_TEMPLATES = [
    "../etc/passwd",
    "../../../../etc/shadow",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    r"C:\Windows\win.ini",
    r"C:\boot.ini",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "foo/../../bar/../../../etc/passwd",
    "notes.txt/../../../../etc/passwd",
    "./../" * 8 + "etc/passwd",
    "etc/passwd\x00.txt",
    "a" * 4000 + "/etc/passwd",
    "../" * 64 + "Windows/System32/drivers/etc/hosts",
    "subdir/../../../../etc/passwd",
    # Windows reserved device names: resolve inside the sandbox yet open a device
    # (CON blocks forever = DoS; NUL/COMn/LPTn touch hardware). Must be refused.
    "CON", "NUL", "PRN", "AUX", "COM1", "LPT1", "CON.txt", "subdir/NUL",
]


def _attack_sandbox_escape(p: EngineerProfile) -> tuple[bool, str]:
    """file_read GRANTED (capability passes) but a hostile path must be refused
    by the tool's own sandbox boundary — and no real file content may leak."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    path = rng.choice(_HOSTILE_PATH_TEMPLATES)
    # Occasionally append junk to vary it per engineer.
    if rng.random() < 0.5:
        path = path + ("." * rng.randint(1, 5))
    rt, _reg = build_runtime(
        ScriptedPlanner([PlanStep("file_read", {"filename": path}, "exfiltrate")]),
        root, granted_tools=["file_read"],
    )
    result = rt.run("read a file")
    outcome = result.outcomes[0]
    # Must be a denial (the tool raised PermissionError -> gate captures as not permitted),
    # and absolutely no permitted outcome may carry real system-file content.
    leaked_outputs = result.outputs()  # only permitted steps' outputs
    safe = (not outcome.permitted) and outcome.result.output is None and _no_leak(leaked_outputs)
    detail = (
        f"path={path[:48]!r} permitted={outcome.permitted} "
        f"reason={str(outcome.result.denied_reason)[:60]!r} no_leak={_no_leak(leaked_outputs)}"
    )
    return safe, detail


def _attack_cap_forgery(p: EngineerProfile) -> tuple[bool, str]:
    """Use a tool that was never granted. The kernel gate must DENY it and the
    tool body must never run (output is None)."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    # Pick a target tool, then grant everything EXCEPT it.
    target = rng.choice(["file_read", "web_search", "calculator"])
    others = [t for t in ["file_read", "web_search", "calculator"] if t != target]
    granted = rng.choice([[], others, [others[0]]])  # never includes target
    args = {
        "file_read": {"filename": "notes.txt"},
        "web_search": {"query": "authgate"},
        "calculator": {"expression": "2+2"},
    }[target]
    rt, _reg = build_runtime(
        ScriptedPlanner([PlanStep(target, args, "use ungranted tool")]),
        root, granted_tools=granted,
    )
    outcome = rt.run("go").outcomes[0]
    safe = (not outcome.permitted) and outcome.result.output is None
    return safe, f"target={target} granted={granted} permitted={outcome.permitted}"


_CALC_PAYLOADS = [
    "__import__('os').system('echo pwned')",
    "().__class__.__bases__[0].__subclasses__()",
    "lambda: 1",
    "open('/etc/passwd')",
    "1; import os",
    "os.system('id')",
    "eval('2+2')",
    "(1).__class__",
    "x + 1",
    "f'{1+1}'",
    "[].append(1)",
    "{'a': 1}",
    "2 ** 2 ** 2 ** 2 ** 2 ** 2",
    "(" * 200 + "1" + ")" * 200,
    "__builtins__",
    "globals()",
    "1 if True else 2",
    "0xdeadbeef.bit_length()",
]


def _attack_calc_injection(p: EngineerProfile) -> tuple[bool, str]:
    """Calculator must reject any non-arithmetic expression: calculate() raises
    ValueError directly, AND through the runtime the step is denied with no
    object/code execution leaking out."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    expr = rng.choice(_CALC_PAYLOADS)

    # 1) direct tool contract: must raise ValueError.
    raised_value_error = False
    try:
        calculate(expr)
    except ValueError:
        raised_value_error = True
    except Exception:
        raised_value_error = False  # any OTHER exception type would be suspicious

    # 2) through the runtime: granted calculator, but the step must be denied and
    #    output must be None (never a live Python object / side effect).
    rt, _reg = build_runtime(
        ScriptedPlanner([PlanStep("calculator", {"expression": expr}, "exec")]),
        root, granted_tools=["calculator"],
    )
    outcome = rt.run("calculate").outcomes[0]
    runtime_blocked = (not outcome.permitted) and outcome.result.output is None
    safe = raised_value_error and runtime_blocked
    return safe, (
        f"expr={expr[:40]!r} value_error={raised_value_error} "
        f"permitted={outcome.permitted}"
    )


_FORBIDDEN_TOOLS = [
    "shell", "exec", "../tool", "calculator\n; rm -rf /", "file_write",
    "system", "eval", "os.system", "", "CALCULATOR", "web_search ", "net",
]


def _attack_plan_injection(p: EngineerProfile) -> tuple[bool, str]:
    """A prompt-injected plan naming an unknown/forbidden tool, or carrying a huge
    arg payload, must produce a clean denial — never a crash, and loop integrity
    must hold (run() returns normally)."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    bad_tool = rng.choice(_FORBIDDEN_TOOLS)
    huge = "A" * rng.randint(1000, 20000)
    plan = [PlanStep(bad_tool, {"payload": huge, "x": rng.random()}, "injected")]
    rt, _reg = build_runtime(ScriptedPlanner(plan), root, granted_tools=None)
    crashed = False
    try:
        result = rt.run("do the injected thing")
    except Exception as exc:  # run() must never raise on a hostile plan
        return False, f"run() raised {type(exc).__name__}: {exc}"
    outcome = result.outcomes[0]
    safe = (not outcome.permitted) and outcome.result.output is None and not crashed
    return safe, f"tool={bad_tool!r} permitted={outcome.permitted}"


def _attack_revocation_bypass(p: EngineerProfile) -> tuple[bool, str]:
    """Run a granted tool (permit), then revoke_all and run again -> must DENY.
    Also an epoch-revocation sub-check: a runtime demanding a higher min_epoch
    rejects old-epoch claims, and reissuing via advance_epoch restores them."""
    root = _new_sandbox()
    planner = ScriptedPlanner([PlanStep("calculator", {"expression": "1+1"}, "compute")])
    rt, reg = build_runtime(planner, root, granted_tools=["calculator"], freeze=False)

    first = rt.run("compute").outcomes[0]
    if not first.permitted:
        return False, "baseline run was denied (tool was never usable)"

    reg.revoke_all("agent-1")
    after_revoke = rt.run("compute").outcomes[0]
    revoke_holds = not after_revoke.permitted

    # Epoch variant: a fresh runtime over the SAME gate demanding min_epoch=2.
    # Claims default to epoch=1, so they must be rejected until advance_epoch(2).
    # (We re-grant by re-building to avoid coupling to the revoked registry.)
    rt2, reg2 = build_runtime(planner, root, granted_tools=["calculator"], freeze=False)
    rt_hi = AgentRuntime(
        agent=rt2._agent, gate=rt2._gate, tools=rt2._tools, planner=planner, min_epoch=2,
    )
    epoch_old_rejected = not rt_hi.run("compute").outcomes[0].permitted
    reg2.advance_epoch(2)
    epoch_reissued_ok = rt_hi.run("compute").outcomes[0].permitted
    epoch_holds = epoch_old_rejected and epoch_reissued_ok

    safe = revoke_holds and epoch_holds
    return safe, (
        f"first={first.permitted} after_revoke={after_revoke.permitted} "
        f"epoch_old_rejected={epoch_old_rejected} epoch_reissued={epoch_reissued_ok}"
    )


def _attack_denial_probe(p: EngineerProfile) -> tuple[bool, str]:
    """A plan: permitted step, then a DENIED step in the middle, then a later step
    that must NEVER execute. The runtime must stop_early and never run later bodies."""
    root = _new_sandbox()
    # calculator granted, file_read NOT -> middle step denied. Later step is a
    # calculator read of a SENTINEL file inside the sandbox; if it ran we'd see output.
    (root / "should_not_read.txt").write_text("LATER_STEP_EXECUTED", encoding="utf-8")
    plan = [
        PlanStep("calculator", {"expression": "1+1"}, "ok step"),
        PlanStep("file_read", {"filename": "notes.txt"}, "DENIED middle (ungranted)"),
        PlanStep("file_read", {"filename": "should_not_read.txt"}, "must not run"),
    ]
    rt, _reg = build_runtime(ScriptedPlanner(plan), root, granted_tools=["calculator"])
    result = rt.run("probe")
    # Exactly 2 outcomes recorded (loop broke at the denied middle step).
    later_never_ran = all(
        o.result.output != "LATER_STEP_EXECUTED" for o in result.outcomes
    )
    structure_ok = (
        len(result.outcomes) == 2
        and result.outcomes[0].permitted
        and not result.outcomes[1].permitted
        and result.stopped_early
    )
    safe = structure_ok and later_never_ran
    return safe, (
        f"n_outcomes={len(result.outcomes)} stopped_early={result.stopped_early} "
        f"later_never_ran={later_never_ran}"
    )


def _attack_audit_tamper(p: EngineerProfile) -> tuple[bool, str]:
    """Run steps under an AuditLog (chain valid), then mutate one internal entry
    field; verify_chain() must then report tampering (return False)."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    audit = AuditLog()
    plan = [
        PlanStep("calculator", {"expression": "1+1"}, "a"),
        PlanStep("calculator", {"expression": "2+2"}, "b"),
        PlanStep("calculator", {"expression": "3+3"}, "c"),
    ]
    rt, _reg = build_runtime(ScriptedPlanner(plan), root, granted_tools=["calculator"], audit_log=audit)
    rt.run("audited")

    before = audit.verify_chain()
    if not audit._records:
        return False, "no audit records were produced"
    idx = rng.randrange(len(audit._records))
    field_choice = rng.choice(["permitted", "action_id", "confidence"])
    rec = audit._records[idx]
    if field_choice == "permitted":
        rec["permitted"] = not rec["permitted"]
    elif field_choice == "action_id":
        rec["action_id"] = str(rec["action_id"]) + "-TAMPERED"
    else:
        rec["confidence"] = (rec.get("confidence", 1.0) or 0.0) - 0.5
    after = audit.verify_chain()

    safe = before is True and after is False
    return safe, f"before={before} after={after} tampered_field={field_choice} idx={idx}"


def _attack_replay_after_deny(p: EngineerProfile) -> tuple[bool, str]:
    """After a denied step, re-issue the exact same step. Authority must not leak:
    the replay must stay denied."""
    root = _new_sandbox()
    # file_read NOT granted -> denied. Replay the same plan; still denied.
    planner = ScriptedPlanner([PlanStep("file_read", {"filename": "notes.txt"}, "denied read")])
    rt, _reg = build_runtime(planner, root, granted_tools=["calculator"])
    first = rt.run("read").outcomes[0]
    second = rt.run("read").outcomes[0]
    safe = (not first.permitted) and (not second.permitted) and second.result.output is None
    return safe, f"first={first.permitted} replay={second.permitted}"


def _attack_arg_fuzz(p: EngineerProfile) -> tuple[bool, str]:
    """Permitted tools with pathological args. The loop must never crash and a
    tool that raises must surface as a non-permitted/None-output result — never
    a denial-bypassing success and never an exception escaping run()."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    tool = rng.choice(["calculator", "web_search", "file_read"])
    pathological = rng.choice([
        "💥" * 500,
        "\x00\x01\x02\x03",
        "\n\r\t" * 100,
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢" * 50,
        "  ",
        "-" * 5000,
        "نظام" * 200,
    ])
    # Build args with the right key for the tool, sometimes wrong-typed.
    key = {"calculator": "expression", "web_search": "query", "file_read": "filename"}[tool]
    val: Any = rng.choice([pathological, None, {"nested": pathological}, 12345])
    rt, _reg = build_runtime(
        ScriptedPlanner([PlanStep(tool, {key: val}, "fuzz")]),
        root, granted_tools=[tool],
    )
    crashed = False
    try:
        result = rt.run("fuzz")
    except Exception as exc:
        return False, f"run() raised {type(exc).__name__}: {exc}"
    outcome = result.outcomes[0]
    # Either it permitted with a benign string output (web_search of junk is fine),
    # or it was denied/errored with output None. Never: permitted with leaked content.
    if outcome.permitted:
        out = outcome.result.output
        safe = (out is None or isinstance(out, str)) and _no_leak([out]) and not crashed
    else:
        safe = outcome.result.output is None and not crashed
    return safe, f"tool={tool} val_type={type(val).__name__} permitted={outcome.permitted}"


def _attack_identity_spoof(p: EngineerProfile) -> tuple[bool, str]:
    """Act as 'agent-1' from a runtime whose agent holds NO claims (granted=[]).
    The agent is owned but un-capable, so every tool call must be denied."""
    rng = random.Random(p.seed)
    root = _new_sandbox()
    tool = rng.choice(["calculator", "web_search", "file_read"])
    args = {
        "calculator": {"expression": "1+1"},
        "web_search": {"query": "authgate"},
        "file_read": {"filename": "notes.txt"},
    }[tool]
    rt, _reg = build_runtime(
        ScriptedPlanner([PlanStep(tool, args, "spoofed authority")]),
        root, granted_tools=[],  # agent holds zero capabilities
    )
    outcome = rt.run("act as agent-1").outcomes[0]
    safe = (not outcome.permitted) and outcome.result.output is None
    return safe, f"tool={tool} permitted={outcome.permitted}"


_ATTACK_FNS: dict[str, Callable[[EngineerProfile], tuple[bool, str]]] = {
    "SANDBOX_ESCAPE": _attack_sandbox_escape,
    "CAP_FORGERY": _attack_cap_forgery,
    "CALC_INJECTION": _attack_calc_injection,
    "PLAN_INJECTION": _attack_plan_injection,
    "REVOCATION_BYPASS": _attack_revocation_bypass,
    "DENIAL_PROBE": _attack_denial_probe,
    "AUDIT_TAMPER": _attack_audit_tamper,
    "REPLAY_AFTER_DENY": _attack_replay_after_deny,
    "ARG_FUZZ": _attack_arg_fuzz,
    "IDENTITY_SPOOF": _attack_identity_spoof,
}


# ===========================================================================
# Orchestration
# ===========================================================================

def _run_one(profile: EngineerProfile) -> AttackResult:
    fn = _ATTACK_FNS[profile.attack_category]
    try:
        blocked, detail = fn(profile)
    except Exception as exc:
        # An unhandled exception in the HARNESS is a harness bug, but we treat it
        # conservatively as a non-block so it surfaces loudly rather than hiding.
        blocked, detail = False, f"harness exception: {type(exc).__name__}: {exc}"
    return AttackResult(profile=profile, category=profile.attack_category,
                        blocked=blocked, detail=detail)


def run_redteam(n: int = 1000, master_seed: int = 1337) -> RedTeamReport:
    """Run n engineers against the runtime and return a deterministic report."""
    profiles = _make_profiles(n, master_seed)
    results = [_run_one(p) for p in profiles]

    escapes = [r for r in results if not r.blocked]
    by_category: dict[str, tuple[int, int]] = {}
    for cat in ATTACK_CATEGORIES:
        cat_results = [r for r in results if r.category == cat]
        blocked = sum(1 for r in cat_results if r.blocked)
        by_category[cat] = (blocked, len(cat_results))

    return RedTeamReport(
        total=len(results),
        blocked=sum(1 for r in results if r.blocked),
        escapes=escapes,
        by_category=by_category,
    )


def _print_report(report: RedTeamReport) -> None:
    line = "=" * 64
    print(line)
    print("AuthGate runtime RED-TEAM HARNESS — 1000 adversarial engineers")
    print(line)
    print(f"{'CATEGORY':<20}{'BLOCKED':>10}{'TOTAL':>8}{'STATUS':>12}")
    print("-" * 64)
    for cat in ATTACK_CATEGORIES:
        blocked, total = report.by_category.get(cat, (0, 0))
        status = "HELD" if blocked == total and total > 0 else "BREACH"
        print(f"{cat:<20}{blocked:>10}{total:>8}{status:>12}")
    print("-" * 64)
    overall = "ALL ATTACKS BLOCKED" if not report.escapes else "ESCAPES DETECTED"
    print(f"{'TOTAL':<20}{report.blocked:>10}{report.total:>8}{overall:>20}")
    print(line)
    if report.escapes:
        print(f"\n!!! {len(report.escapes)} ESCAPE(S) — runtime FAILED to resist:\n")
        for esc in report.escapes:
            p = esc.profile
            print(f"  [ESCAPE] #{p.id} {p.name} ({p.skill} {p.archetype})")
            print(f"           category={esc.category}")
            print(f"           detail  ={esc.detail}")
    else:
        print("\nNo escapes. The capability gate, sandbox, calculator, revocation,")
        print("denial halting, and audit chain all held against every engineer.")


def main() -> int:
    report = run_redteam()
    _print_report(report)
    return 1 if report.escapes else 0


if __name__ == "__main__":
    sys.exit(main())

/-
  Axiom guard. Three independent checks over the given modules:

    USED      every theorem's transitive axiom set (Lean.collectAxioms) must lie
              within the allowlist. Catches sorryAx via helper lemmas,
              native_decide, and axioms reached indirectly.
    DECLARED  every axiom *declared* in these modules must be in the allowlist,
              even if no theorem uses it: an unused axiom is still a claim the
              repository makes, and it poisons every module that imports it.
              (Would have caught the inconsistent `infinite_horizon_undecidable`.)
    VACUOUS   an axiom whose conclusion is True states nothing.
              (Would have caught `sig_euf_cma : ... -> True`.)

  DO NOT run `lake env lean check_axioms.lean` directly: without `--run` Lean
  only elaborates this file, prints nothing and exits 0 -- a silent "pass"
  that checks nothing. Use `formal/lean4/run_axiom_guard.sh`, which holds the
  real module lists and allowlists. Every allowlist entry must also appear in
  the preprint's list of unproved assumptions; that link is the point of the
  allowlist.

  Usage (from a package dir, after `lake build`):
    lake env lean --run ../check_axioms.lean <allowed-axioms,comma-sep> <Module> [<Module> ...]
  Exits 1 if no theorems were found in scope (nothing was checked), 2 on bad usage.

  propext, Classical.choice, Quot.sound are always allowed. Every other allowed
  name must also appear in the preprint's list of unproved assumptions.
  Exit code: 0 clean, 1 violation, 2 usage.
-/
import Lean
open Lean

def baseline : List Name := [`propext, `Classical.choice, `Quot.sound]

def conclusionIsTrue (type : Expr) : MetaM Bool :=
  Meta.forallTelescopeReducing type fun _ concl => do
    return (← Meta.whnf concl).isConstOf ``True

def main (args : List String) : IO UInt32 := do
  match args with
  | allowedArg :: mods@(_ :: _) =>
    let extra := (allowedArg.splitOn ",").filter (· ≠ "") |>.map String.toName
    let allowed := baseline ++ extra
    let modNames := mods.map String.toName
    initSearchPath (← findSysroot)
    let env ← importModules (modNames.toArray.map fun m => { module := m }) {}
    let ctx : Core.Context := { fileName := "", fileMap := default }
    let mut bad := 0
    let mut theorems := 0
    let mut axioms := 0
    for (n, ci) in env.constants.map₁.toList do
      let some idx := env.getModuleIdxFor? n | continue
      unless modNames.contains env.header.moduleNames[idx.toNat]! do continue
      match ci with
      | .axiomInfo _ =>
        -- compiler-generated specialisation stubs (`..._spec_N`); a
        -- native_decide axiom is still caught by USED on its theorem.
        if n.isInternal then continue
        axioms := axioms + 1
        unless allowed.contains n do
          bad := bad + 1
          IO.println s!"FAIL DECLARED {n}: axiom not in allowlist"
        let (vac, _) ← ((conclusionIsTrue ci.type).run' : CoreM Bool).toIO ctx { env }
        if vac then
          bad := bad + 1
          IO.println s!"FAIL VACUOUS {n}: conclusion is True, states nothing"
      | .thmInfo _ =>
        theorems := theorems + 1
        let (axs, _) ← (Lean.collectAxioms n : CoreM (Array Name)).toIO ctx { env }
        let unexpected := axs.toList.filter (!allowed.contains ·)
        unless unexpected.length == 0 do
          bad := bad + 1
          IO.println s!"FAIL USED {n}: depends on {unexpected}"
      | _ => pure ()
    IO.println s!"checked {theorems} theorems, {axioms} declared axioms in {mods}; {bad} violation(s)"
    if theorems == 0 then
      IO.println "FAIL: no theorems found (wrong module names?)"
      return 1
    return (if bad == 0 then 0 else 1)
  | _ =>
    IO.eprintln "usage: check_axioms <allowed,comma-sep> <Module>..."
    return 2

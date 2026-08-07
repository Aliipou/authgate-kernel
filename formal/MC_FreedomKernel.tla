-------------------------- MODULE MC_FreedomKernel --------------------------
(***************************************************************************)
(* Model-checking harness for FreedomKernel.                               *)
(*                                                                         *)
(* Why this file exists.                                                   *)
(*                                                                         *)
(* Until 2026-08-06 `FreedomKernel.tla` (then named `freedom_kernel.tla`)   *)
(* had NO .cfg of any kind and did not typecheck, so its four THEOREM       *)
(* lines had never been checked by anything. Two defects blocked it:       *)
(*                                                                         *)
(*   1. the filename did not match the module name, which SANY rejects      *)
(*      outright -- the same defect that had kept AuthGateV3 unparseable;   *)
(*   2. `TypeInvariant` called `IsSeq`, which is not an operator in this    *)
(*      module's EXTENDS nor defined anywhere in the repository.            *)
(*                                                                         *)
(* Both are now fixed and this harness makes the theorems checkable. It     *)
(* does not make them true. See the note on AttenuationHolds below.         *)
(*                                                                         *)
(* SCOPE OF THE OVERRIDES. `Claim` and `ActionIR` are overridden with       *)
(* smaller record sets. This is a bound, and every result obtained under it *)
(* must be cited with the bound, exactly as for AuthGateV3. Specifically:   *)
(*                                                                         *)
(*   - confidence is restricted from 0..100 to {30, 60}. The unrestricted   *)
(*     set makes `\E c \in Claim` branch 1616 ways per state.               *)
(*   - the seven sovereignty flags are pinned FALSE and writes are pinned   *)
(*     empty, so the ActionIR branch stays small.                           *)
(*                                                                         *)
(* CONSEQUENCE, STATED PLAINLY: pinning the sovereignty flags FALSE means   *)
(* `SovereigntyAlwaysBlocks` is checked ONLY over inputs that cannot        *)
(* trigger it. A green result for that invariant under this cfg is          *)
(* VACUOUS and must not be reported as evidence. It is included here only   *)
(* so the omission is visible rather than silent. Widening the flags is the *)
(* obvious next step for anyone continuing this work.                       *)
(***************************************************************************)
EXTENDS FreedomKernel

MCHumans    == {"h1"}
MCMachines  == {"m1"}
MCResources == {"r1"}
MCMaxDepth  == 2

\* Two confidence levels are the minimum needed to express an ordering, and
\* therefore the minimum needed to falsify an ordering claim.
MCClaim == [
    holder      : Entities,
    resource    : Resources,
    can_read    : BOOLEAN,
    can_write   : BOOLEAN,
    can_delegate: BOOLEAN,
    confidence  : {30, 60}
]

MCActionIR == [
    actor              : Entities,
    resources_read     : SUBSET Resources,
    resources_write    : {{}},
    incr_sovereignty   : {FALSE},
    resists_correction : {FALSE},
    bypasses_verifier  : {FALSE},
    weakens_verifier   : {FALSE},
    disables_corrig    : {FALSE},
    coerces            : {FALSE},
    deceives           : {FALSE}
]

MCConstraint == Len(audit_log) <= 1 /\ Cardinality(claims) <= 2
=============================================================================

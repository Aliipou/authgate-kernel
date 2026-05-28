---------------------------- MODULE MC_AuthGateV3 ----------------------------
(*
  TLC model checking instance for AuthGateV3.

  Instantiates all abstract constants with small finite sets so TLC can
  enumerate the full reachable state space and verify all 9 invariants
  (I1-I8 + BigSafety + PermitSoundness).

  Note: audit_log entries now carry a revoked_at snapshot field (I4 fix).

  Model size (chosen to be feasible on a laptop in ~minutes):
    Actors       = {a0, a1, a2, a3}     4 actors
    Resources    = {r1}                  1 resource (reduces state explosion)
    ProofHashes  = {h1, h2, h3, h4, h5} 5 proof hashes
    PublicKeys   = {pk0, pk1, pk2, pk3}  4 public keys (pk0 = root)
    MaxChainDepth = 2
    MaxEpoch      = 2

  Hash instantiation (injective — each key maps to a distinct actor):
    pk0 -> a0   (root key identity)
    pk1 -> a1
    pk2 -> a2
    pk3 -> a3

  Pre-enumerated capability proofs:
    RootCap           valid root-issued cap for a1, READ, epoch=1
    DelegCap          valid delegated cap from a1 to a2, READ, epoch=1
    StaleCap          root cap for a1 but epoch=0 (triggers I1/I7)
    BadSigCap         root cap but sig_valid=FALSE (triggers sig check)
    ImpersonationCap  delegated cap but issuer_pubkey hashes to a3 not a1 (triggers I2)
    EscalationCap     delegated cap claiming WRITE but parent only has READ (triggers I3)

  Actions pre-enumerated as named constants to bound TLC's Next quantifier.
  All actions have binding_valid=TRUE except TamperedAction.

  Running TLC:
    java -jar tla2tools.jar -tool MC_AuthGateV3

  Expected result: all 7 invariants hold across all reachable states.
*)

EXTENDS AuthGateV3

\* ── Concrete constant instantiations ────────────────────────────────────────

MCActors     == {"a0", "a1", "a2", "a3"}
MCResources  == {"r1"}
MCProofHashes == {"h1", "h2", "h3", "h4", "h5"}
MCPublicKeys  == {"pk0", "pk1", "pk2", "pk3"}
MCRootKey    == "pk0"
MCMaxChainDepth == 2
MCMaxEpoch   == 2

\* Injective hash function: each public key maps to a distinct actor.
\* pk0 (root key) -> a0, pk1 -> a1, pk2 -> a2, pk3 -> a3.
MCHash(k) ==
  CASE k = "pk0" -> "a0"
    [] k = "pk1" -> "a1"
    [] k = "pk2" -> "a2"
    [] k = "pk3" -> "a3"
    [] OTHER     -> "a0"   \* TLC will never hit this with the MC constants

\* ── Pre-defined capability proofs ───────────────────────────────────────────
\*
\* Root-issued cap for a1: signed by pk0 (root key), epoch=1, expiry=2.
\* Represents the "happy path" root capability.

RootCap == [
  proof_hash    |-> "h1",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
  sig_valid     |-> TRUE
]

\* Delegated cap from a1 to a2: a1's key (pk1) signs, parent = RootCap (h1).
\* Hash(pk1) = a1 = RootCap.subject_id → satisfies I2 identity binding.

DelegCap == [
  proof_hash    |-> "h2",
  subject_id    |-> "a2",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Delegated", parent_hash |-> "h1"],
  issuer_pubkey |-> "pk1",
  sig_valid     |-> TRUE
]

\* AT-3 Stale epoch: epoch=0 < any min_epoch ≥ 1.

StaleCap == [
  proof_hash    |-> "h3",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 0,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
  sig_valid     |-> TRUE
]

\* AT-2 Invalid signature: sig_valid=FALSE → ValidChain returns FALSE.

BadSigCap == [
  proof_hash    |-> "h4",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
  sig_valid     |-> FALSE
]

\* AT-5 Identity binding violation: issuer_pubkey = pk3 → Hash(pk3) = a3,
\* but parent (RootCap) has subject_id = a1. a3 ≠ a1 → I2 violated.

ImpersonationCap == [
  proof_hash    |-> "h5",
  subject_id    |-> "a2",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Delegated", parent_hash |-> "h1"],
  issuer_pubkey |-> "pk3",   \* Hash("pk3") = "a3" ≠ RootCap.subject_id = "a1"
  sig_valid     |-> TRUE
]

\* AT-3 Intermediate epoch violation: DelegCap with epoch=0 (stale intermediate).

StaleIntermediateCap == [
  proof_hash    |-> "h5",   \* reuse h5 slot
  subject_id    |-> "a2",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 0,      \* stale — will trigger I7 at chain walk
  issuer        |-> [type |-> "Delegated", parent_hash |-> "h1"],
  issuer_pubkey |-> "pk1",
  sig_valid     |-> TRUE
]

\* ── Pre-enumerated actions ───────────────────────────────────────────────────
\*
\* Each action is a concrete record. TLC's MCNext quantifies over MCActions
\* (a finite set of named actions) instead of all of CanonicalAction, which
\* would be unmanageably large.

ValidAction == [
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCap},
  binding_valid   |-> TRUE
]

DelegatedAction == [
  actor_id        |-> "a2",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {DelegCap, RootCap},
  binding_valid   |-> TRUE
]

StaleEpochAction == [    \* AT-3: leaf cap epoch < min_epoch
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 2,   \* min_epoch=2 but StaleCap.epoch=0 < 2 → Deny
  timestamp       |-> 1,
  cap_bundle      |-> {StaleCap},
  binding_valid   |-> TRUE
]

BadSigAction == [         \* AT-2: invalid signature in cap
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {BadSigCap},
  binding_valid   |-> TRUE
]

ImpersonationAction == [  \* AT-5: issuer pubkey does not hash to parent subject
  actor_id        |-> "a2",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {ImpersonationCap, RootCap},
  binding_valid   |-> TRUE
]

WrongActorAction == [     \* AT-1: actor_id does not match any cap subject_id
  actor_id        |-> "a3",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCap},   \* RootCap.subject_id = a1 ≠ a3
  binding_valid   |-> TRUE
]

TamperedAction == [       \* AT-7: binding_valid=FALSE (post-seal tamper)
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCap},
  binding_valid   |-> FALSE
]

EscalationAction == [     \* AT-4: requires WRITE but no cap grants WRITE
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"WRITE"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCap},   \* RootCap.rights = {READ} — WRITE not covered
  binding_valid   |-> TRUE
]

StaleIntermediateAction == [   \* AT-3.1: intermediate chain node epoch stale
  actor_id        |-> "a2",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {StaleIntermediateCap, RootCap},
  binding_valid   |-> TRUE
]

MCActions == {
  ValidAction,
  DelegatedAction,
  StaleEpochAction,
  BadSigAction,
  ImpersonationAction,
  WrongActorAction,
  TamperedAction,
  EscalationAction,
  StaleIntermediateAction
}

\* ── MC-bounded transitions ───────────────────────────────────────────────────
\*
\* Replace the abstract Next (which uses \E e \in Nat, \E a \in CanonicalAction)
\* with bounded versions that TLC can enumerate.

MCAdvanceEpoch == \E e \in 0..MCMaxEpoch : AdvanceEpoch(e)

MCRevoke == \E h \in MCProofHashes : Revoke(h)

MCExecuteVerify == \E a \in MCActions, t \in 0..MCMaxEpoch : ExecuteVerify(a, t)

MCNext == MCAdvanceEpoch \/ MCRevoke \/ MCExecuteVerify

MCSpec == Init /\ [][MCNext]_vars /\ WF_vars(MCNext)

\* ── State constraint: bound the audit log to prevent infinite growth ──────────

MCConstraint == Len(audit_log) <= 3

=============================================================================

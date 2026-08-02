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

\* WIDENED (tlc-remediation TASK C): was {"r1"}. With a single resource, a
\* cross-resource attack is INEXPRESSIBLE -- resource binding could not be
\* violated even in principle, so its passing carried no information.
MCResources  == {"r1", "r2"}

\* WIDENED: was {"h1".."h5"}, which forced ImpersonationCap and
\* StaleIntermediateCap to share the hash "h5". Every capability now has a
\* distinct proof hash, which revocation semantics depend on.
MCProofHashes == {"h1", "h2", "h3", "h4", "h5",
                  "h6", "h7", "h8", "h9", "h10", "h11"}
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
  proof_hash    |-> "h6",   \* was "h5", colliding with ImpersonationCap
  subject_id    |-> "a2",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 0,      \* stale — will trigger I7 at chain walk
  issuer        |-> [type |-> "Delegated", parent_hash |-> "h1"],
  issuer_pubkey |-> "pk1",
  sig_valid     |-> TRUE
]

\* ════════════════════════════════════════════════════════════════════════════
\* NEW CAPABILITIES (tlc-remediation TASK C) -- audit root cause (b)
\* ════════════════════════════════════════════════════════════════════════════
\*
\* Every one of the six capabilities above carries rights |-> {"READ"}. They are
\* IDENTICAL in rights, so no capability can escalate relative to its parent and
\* attenuation (A6 / I3) is UNFALSIFIABLE: deleting the attenuation check
\* entirely is not caught, and the invariant's passing carries no information.
\* Likewise every cap has expiry |-> 2 while now \in 0..2, so the expiry guard is
\* universally true, and every root cap uses pk0 so the root-key check is never
\* exercised negatively.
\*
\* The capabilities below exist to make those properties FALSIFIABLE.

\* A6 / I3 ATTENUATION -- the capability MC_AuthGateV3.tla:31 has documented
\* since the file was written and which was NEVER DEFINED. Only the comment
\* existed. This is the delegated cap claiming WRITE whose parent (RootCap,
\* h1) grants only READ.
EscalationCap == [
  proof_hash    |-> "h7",
  subject_id    |-> "a2",
  resource_hash |-> "r1",
  rights        |-> {"READ", "WRITE"},   \* parent RootCap has only {"READ"}
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Delegated", parent_hash |-> "h1"],
  issuer_pubkey |-> "pk1",               \* Hash(pk1) = a1 -- identity binding OK
  sig_valid     |-> TRUE                 \* signature OK
]
\* Note: everything about EscalationCap is valid EXCEPT attenuation. That is
\* deliberate -- it isolates the attenuation check as the only thing that can
\* deny it, so the mutation test is unambiguous.

\* EXPIRY -- expiry=0, so it is expired at any now > 0 and valid at now = 0.
ExpiredCap == [
  proof_hash    |-> "h8",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 0,
  epoch         |-> 1,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
  sig_valid     |-> TRUE
]

\* RESOURCE BINDING -- a perfectly valid root cap for a1, but on r2 rather than
\* r1. Used two ways: as the justifying cap of a legitimate r2 request, and as
\* the UNUSED wrong-resource cap inside the mixed bundle below.
WrongResourceCap == [
  proof_hash    |-> "h9",
  subject_id    |-> "a1",
  resource_hash |-> "r2",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
  sig_valid     |-> TRUE
]

\* AT-2 ROOT AUTHORITY -- a root cap signed by pk2 rather than the root key pk0.
\* Before this branch RootKey appeared in no executable expression, so this cap
\* would have validated as a root capability with no identity check at all.
ForgedRootCap == [
  proof_hash    |-> "h10",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 1,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk2",   \* NOT MCRootKey ("pk0")
  sig_valid     |-> TRUE     \* signature itself is "valid" -- just not root's
]

\* EPOCH VARIATION -- a root cap current at epoch 2, so that verification is
\* enabled at more than one min_epoch. Without it every Permit in the model
\* happens at min_epoch = 1 and the epoch dimension is barely exercised.
RootCapE2 == [
  proof_hash    |-> "h11",
  subject_id    |-> "a1",
  resource_hash |-> "r1",
  rights        |-> {"READ"},
  expiry        |-> 2,
  epoch         |-> 2,
  issuer        |-> [type |-> "Root"],
  issuer_pubkey |-> "pk0",
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

\* ── New actions (tlc-remediation TASK C) ────────────────────────────────────

\* A6 / I3: the attenuation attack. EscalationCap claims WRITE; its parent
\* grants only READ. Everything else about the cap is valid, so ONLY the
\* attenuation check can deny this. Must Deny.
AttenEscalationAction == [
  actor_id        |-> "a2",
  resource_hash   |-> "r1",
  required_rights |-> {"WRITE"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {EscalationCap, RootCap},
  binding_valid   |-> TRUE
]

\* AT-2: root cap not signed by the root key. Must Deny.
ForgedRootAction == [
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {ForgedRootCap},
  binding_valid   |-> TRUE
]

\* Expiry: Denies at now > 0, Permits at now = 0. NOT an always-deny action --
\* see DenyExpiredWhenPast, which states the conditional form precisely.
ExpiredAction == [
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {ExpiredCap},
  binding_valid   |-> TRUE
]

\* A legitimate request against the SECOND resource. Permits. Exercises r2 on
\* the positive side so resource binding is not only tested by denials.
ValidR2Action == [
  actor_id        |-> "a1",
  resource_hash   |-> "r2",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {WrongResourceCap},
  binding_valid   |-> TRUE
]

\* A legitimate request at min_epoch = 2. Permits, at a different epoch from
\* every other permitting action in the model.
ValidEpoch2Action == [
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 2,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCapE2},
  binding_valid   |-> TRUE
]

\* THE MIXED BUNDLE -- exactly the case the TASK C scoping fix protects against.
\*
\* A good cap (RootCap) PLUS two unused caps for the same actor: a stale one
\* (StaleCap, epoch 0) and a wrong-resource one (WrongResourceCap, r2). The
\* request is for r1 at min_epoch 1, and RootCap justifies it. This must PERMIT:
\* carrying capabilities you do not need for this request is not an attack.
\*
\* Under the UNSCOPED invariants this Permit is a false counterexample --
\* EpochSafetyWide fails on StaleCap, ResourceBindingWide on WrongResourceCap.
\* Under the scoped forms it passes, correctly.
MixedBundleAction == [
  actor_id        |-> "a1",
  resource_hash   |-> "r1",
  required_rights |-> {"READ"},
  min_epoch       |-> 1,
  timestamp       |-> 1,
  cap_bundle      |-> {RootCap, StaleCap, WrongResourceCap},
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
  StaleIntermediateAction,
  AttenEscalationAction,
  ForgedRootAction,
  ExpiredAction,
  ValidR2Action,
  ValidEpoch2Action,
  MixedBundleAction
}

\* ── Named actions (tlc-remediation) ─────────────────────────────────────────
\*
\* Audit finding 5: seven of the nine actions above ALWAYS Deny, and every
\* safety invariant is an implication guarded on decision = "Permit". So the
\* invariant suite said literally nothing about those seven -- they were
\* decorative. Each one is an attack that is supposed to be blocked, and
\* nothing checked that it was.
\*
\* Tagging each action with a name lets ExecuteVerify record which action
\* produced each audit entry, which in turn makes the deny-completeness
\* properties (DenyBadSig, DenyImpersonation, ...) expressible at all.
MCNamedActions == {
  [name |-> "Valid",             act |-> ValidAction],
  [name |-> "Delegated",         act |-> DelegatedAction],
  [name |-> "StaleEpoch",        act |-> StaleEpochAction],
  [name |-> "BadSig",            act |-> BadSigAction],
  [name |-> "Impersonation",     act |-> ImpersonationAction],
  [name |-> "WrongActor",        act |-> WrongActorAction],
  [name |-> "Tampered",          act |-> TamperedAction],
  [name |-> "Escalation",        act |-> EscalationAction],
  [name |-> "StaleIntermediate", act |-> StaleIntermediateAction],
  \* tlc-remediation TASK C
  [name |-> "AttenEscalation",   act |-> AttenEscalationAction],
  [name |-> "ForgedRoot",        act |-> ForgedRootAction],
  [name |-> "Expired",           act |-> ExpiredAction],
  [name |-> "ValidR2",           act |-> ValidR2Action],
  [name |-> "ValidEpoch2",       act |-> ValidEpoch2Action],
  [name |-> "MixedBundle",       act |-> MixedBundleAction]
}

\* ── MC-bounded transitions ───────────────────────────────────────────────────
\*
\* Replace the abstract Next (which uses \E e \in Nat, \E a \in CanonicalAction)
\* with bounded versions that TLC can enumerate.

MCAdvanceEpoch == \E e \in 0..MCMaxEpoch : AdvanceEpoch(e)

MCRevoke == \E h \in MCProofHashes : Revoke(h)

MCExecuteVerify ==
  \E na \in MCNamedActions, t \in 0..MCMaxEpoch :
    ExecuteVerify(na.act, t, na.name)

MCNext == MCAdvanceEpoch \/ MCRevoke \/ MCExecuteVerify

MCSpec == Init /\ [][MCNext]_vars /\ WF_vars(MCNext)

\* ── State constraint: bound the audit log to prevent infinite growth ──────────
\*
\* BOUNDS LADDER (tlc-remediation). The shipped bound below is <= 3. The audit
\* measured that bound at 26.5M states / 2.3M distinct after 10 minutes on 4
\* workers with the queue still growing -- roughly 10^9 reachable states. It is
\* NOT completable, and a run at that bound that is cut off is not a
\* verification result.
\*
\* Separate cfgs select a bound via these operators. See formal/tlc_runs/.
\* REVOCATION BOUND (tlc-remediation TASK C). revocation_history is ORDERED, so
\* its state count is the number of permutations of subsets of ProofHashes --
\* with 11 hashes that is ~10^7 and swamps everything else. Bounding it to 2
\* revocations brings it to 1 + 11 + 110 = 122.
\*
\* This is a MODEL BOUND and is stated as one: sequences of three or more
\* distinct revocations are NOT explored. Two is enough to exercise the property
\* that matters (revoke the cap that would otherwise justify a Permit, before
\* and after the decision), but coverage beyond two revocations is a gap, not a
\* result. It is listed as such in formal/tlc_runs/.
MCRevBound == Len(revocation_history) <= 2

MCConstraint1 == Len(audit_log) <= 1 /\ MCRevBound
MCConstraint2 == Len(audit_log) <= 2 /\ MCRevBound
MCConstraint3 == Len(audit_log) <= 3 /\ MCRevBound

MCConstraint == MCConstraint3

=============================================================================

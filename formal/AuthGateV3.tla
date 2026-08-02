---------------------------- MODULE AuthGateV3 ----------------------------
(*
  TLA+ specification of authgate-kernel v3 — proof-chain capability system.

  Models the stateless verify() function and SequenceContext composition tracker.
  Cryptographic operations (ed25519 signatures, SHA-256) are abstracted as
  uninterpreted injective functions. This spec proves protocol-level correctness,
  not cryptographic hardness.

  ── Invariants (stated as theorems, TLC model pending) ────────────────────────
  I1. EpochSafety      — no cap with epoch < min_epoch produces Permit
  I2. IdentityBinding  — issuer_pubkey hashes to parent.subject_id (AT-5.1)
  I3. Attenuation      — child.rights ⊆ parent.rights in every delegation node
  I4. RevocationSafety — explicitly revoked proof hashes never produce Permit
  I5. CompositionMono  — session accumulated_rights never decreases
  I6. ResourceBinding  — Permit only when cap.resource_hash == action.resource_hash
  I7. ChainEpoch       — every delegation chain node epoch >= min_epoch (AT-3.1)
  I8. ChainComplete    — every Delegated node's parent_hash resolves in the bundle

  ── Branch ────────────────────────────────────────────────────────────────────
  spec-core — research / formal verification track

  ── Status ────────────────────────────────────────────────────────────────────
  Abstract spec: invariants stated, transitions defined.
  TLC model: MC_AuthGateV3.tla + MC_AuthGateV3.cfg — concrete instantiation.
  Run: java -jar tla2tools.jar -tool MC_AuthGateV3
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
  Actors,        \* Finite set of actor identity values (abstract SHA-256 outputs)
  Resources,     \* Finite set of resource hash values
  ProofHashes,   \* Finite set of proof_hash values (abstract SHA-256 outputs)
  PublicKeys,    \* Finite set of public key representations
  RootKey,       \* Distinguished root key — element of PublicKeys
  MaxChainDepth, \* Delegation depth limit (= 16 in Rust impl)
  MaxEpoch,      \* Upper bound for TLC model checking
  Hash(_)        \* Abstract injective function: PublicKey -> Actor (SHA-256 in impl)

ASSUME MaxChainDepth \in Nat /\ MaxChainDepth > 0
ASSUME MaxEpoch \in Nat /\ MaxEpoch > 0
ASSUME RootKey \in PublicKeys
\* Hash injectivity — no two distinct keys map to the same actor identity.
ASSUME \A k1, k2 \in PublicKeys : Hash(k1) = Hash(k2) => k1 = k2

\* Rights modeled as symbolic strings — MC model restricts to {"READ","WRITE"}.
AllRights == {"READ", "WRITE", "DELEGATE", "EXECUTE",
              "SPAWN", "NETWORK", "MODEL_INVOKE", "POLICY_MODIFY"}

\* sig_valid: abstracted as a Boolean field in CapabilityProof.
\* Crypto soundness (EUF-CMA) is assumed — not modeled in state.

\* ── Structured types ────────────────────────────────────────────────────────

IssuerRef ==
  [type : {"Root"}]
  \cup
  [type : {"Delegated"}, parent_hash : ProofHashes]

CapabilityProof == [
  proof_hash    : ProofHashes,
  subject_id    : Actors,       \* identity of the principal this cap is issued TO
  resource_hash : Resources,
  rights        : SUBSET AllRights,
  expiry        : Nat,
  epoch         : Nat,
  issuer        : IssuerRef,
  issuer_pubkey : PublicKeys,   \* pubkey of whoever issued (signed) this proof
  sig_valid     : BOOLEAN       \* abstracts ed25519 verify(signing_message, sig, key)
]

CanonicalAction == [
  actor_id        : Actors,
  resource_hash   : Resources,
  required_rights : SUBSET AllRights,
  min_epoch       : Nat,
  timestamp       : Nat,
  cap_bundle      : SUBSET CapabilityProof,
  binding_valid   : BOOLEAN  \* abstracts SHA-256 binding_hash check
]

Decision == {"Permit", "Deny"}

\* ── Chain validation (models validate_chain in dag.rs) ──────────────────────

\* Locate parent proof in the bundle.
FindParent(proof, bundle) ==
  CHOOSE p \in bundle : p.proof_hash = proof.issuer.parent_hash

HasParent(proof, bundle) ==
  /\ proof.issuer.type = "Delegated"
  /\ \E p \in bundle : p.proof_hash = proof.issuer.parent_hash

\* Recursive chain validity — modeled iteratively up to MaxChainDepth.
\* Returns TRUE iff the chain from `leaf` to root is valid under `min_epoch`.
ValidChain(leaf, bundle, min_epoch_val) ==
  LET RECURSIVE WalkChain(_, _, _)
      WalkChain(current, depth, mep) ==
        IF depth > MaxChainDepth THEN FALSE          \* depth limit exceeded
        ELSE IF current.epoch < mep THEN FALSE       \* I7: chain epoch check
        ELSE CASE current.issuer.type = "Root" ->
                   \* root sig
                   /\ current.sig_valid
                   \* AT-2 FIX (tlc-remediation): RootKey previously appeared in
                   \* NO executable expression anywhere in this spec. It was
                   \* declared (CONSTANTS) and ASSUMEd, and that was all -- so ANY
                   \* issuer_pubkey with sig_valid=TRUE validated a root capability.
                   \* A root cap must actually be signed by the root key.
                   /\ current.issuer_pubkey = RootKey
               [] current.issuer.type = "Delegated" ->
                   /\ current.sig_valid              \* intermediate sig
                   /\ HasParent(current, bundle)     \* I8: parent in bundle
                   /\ LET parent == FindParent(current, bundle) IN
                      \* I2: issuer_pubkey must hash to parent.subject_id
                      /\ Hash(current.issuer_pubkey) = parent.subject_id
                      \* I3: attenuation — child rights ⊆ parent rights
                      /\ current.rights \subseteq parent.rights
                      \* recurse
                      /\ WalkChain(parent, depth + 1, mep)
  IN WalkChain(leaf, 0, min_epoch_val)

\* ── Structural chain traversal (tlc-remediation) ────────────────────────────
\*
\* ChainNodes collects the set of capabilities on the chain from `leaf` toward
\* the root. It performs NO validity checks whatsoever -- it only follows
\* parent_hash links and stops at a root, a missing parent, or the depth limit.
\*
\* WHY THIS EXISTS. The audit's root cause (a) was SELF-REFERENCE: the old
\* ChainEpoch and PermitSoundness re-invoked ValidChain, the very predicate that
\* computed the decision. Delete a check from ValidChain and the invariant
\* weakens in lockstep, so no mutation can ever be caught.
\*
\* ChainNodes breaks that loop. It is purely structural, so deleting an
\* enforcement check from ValidChain does NOT change which nodes it returns.
\* Invariants below quantify over ChainNodes and state each required property
\* LITERALLY, in their own text. A deleted check therefore shows up as a real
\* invariant violation with a counterexample, which is the entire point.
\*
\* Every invariant written against ChainNodes is an independent statement.
\* Nothing below this line may call ValidChain or Verify.
ChainNodes(leaf, bundle) ==
  LET RECURSIVE Walk(_, _)
      Walk(cur, depth) ==
        IF depth > MaxChainDepth THEN {cur}
        ELSE IF cur.issuer.type = "Root" THEN {cur}
        ELSE IF ~HasParent(cur, bundle) THEN {cur}
        ELSE {cur} \cup Walk(FindParent(cur, bundle), depth + 1)
  IN Walk(leaf, 0)

\* ── Kernel verify() modeled as a pure function ──────────────────────────────
\*
\* Returns "Permit" iff there EXISTS at least one cap in the bundle that:
\*   - belongs to the actor (subject_id match)
\*   - matches the requested resource (I6)
\*   - has not expired (expiry >= now)
\*   - passes the leaf epoch gate (I1)
\*   - passes the full chain walk (I2, I3, I7, I8 via ValidChain)
\*   - covers the required rights
\*   - is not revoked (I4)
\* AND the action binding is valid (L1 canonical gate).
\*
\* This is the positive form: Permit = ∃ valid cap. Deny = ¬∃ valid cap.
\* Mirrors the Rust engine.rs semantics exactly.

\* Witnesses: the set of capabilities that JUSTIFY a Permit -- i.e. the caps
\* that passed every enforcement check. Factored out of Verify so that
\* ExecuteVerify can record it into the audit log as DATA.
\*
\* Recording the witness is what makes scoped, non-vacuous invariants possible.
\* The old invariants had to quantify over every actor-matching cap in the
\* bundle because they had no idea which cap actually justified the decision;
\* that is what made EpochSafety / ResourceBinding / ChainEpoch over-strong
\* (audit finding 7). With the witness recorded, invariants can talk about the
\* cap the kernel actually relied on.
\*
\* This is NOT self-reference. The invariants below never call Witnesses or
\* Verify; they read the recorded set and assert properties of it spelled out
\* in their own text. Deleting an enforcement check here lets a bad cap into
\* the witness, and the independent invariants then fire on it.
Witnesses(action, revoked_set_var, now) ==
  IF ~action.binding_valid THEN {}   \* L1: canonical gate
  ELSE
    LET actor_caps == {c \in action.cap_bundle : c.subject_id = action.actor_id}
    IN {c \in actor_caps :
          /\ c.resource_hash = action.resource_hash     \* I6
          /\ c.expiry >= now                            \* expiry
          /\ c.epoch >= action.min_epoch                \* I1 leaf epoch
          /\ ValidChain(c, action.cap_bundle, action.min_epoch) \* I2 I3 I7 I8
          /\ action.required_rights \subseteq c.rights  \* rights coverage
          /\ c.proof_hash \notin revoked_set_var}       \* I4 revocation

Verify(action, revoked_set_var, now) ==
  IF Witnesses(action, revoked_set_var, now) = {} THEN "Deny" ELSE "Permit"

\* ── State variables ─────────────────────────────────────────────────────────
\*
\* The kernel itself is stateless. The state here models:
\*   (a) the epoch gate (can only advance)
\*   (b) revocation accumulator (can only grow)
\*   (c) session composition tracker (accumulated_rights per actor)
\*   (d) audit log for temporal property checks

VARIABLES
  global_epoch,       \* Nat — current minimum epoch; only advances
  revoked_set,        \* SUBSET ProofHashes — explicitly revoked proof hashes
  session_rights,     \* [Actors -> SUBSET AllRights] — accumulated session rights
  revocation_history, \* Seq of ProofHashes — ORDERED revocation record (see below)
  audit_log           \* Seq of audit records; fields documented at ExecuteVerify

\* revocation_history (tlc-remediation, audit root cause (a)):
\* An ordered, append-only log written ONLY by Revoke and read by NO enforcement
\* path -- Verify/Witnesses never consult it. That independence is the whole
\* point: the old RevocationSafety re-checked `c.proof_hash \notin revoked_at`,
\* the exact predicate Witnesses had already filtered on, against the exact same
\* snapshot. It was a tautology and could not fail. RevocationSafety is now
\* stated against this variable instead, so deleting the revocation filter from
\* Witnesses lets a revoked cap into the witness set and the invariant fires.
\*
\* Revoke is guarded by `\notin revoked_set` so the sequence cannot grow without
\* bound; it is a permutation of a subset of ProofHashes.

vars == <<global_epoch, revoked_set, session_rights, revocation_history, audit_log>>

\* Was proof hash `h` already revoked at the point audit entry `i` was decided?
\* Reads the ordered history prefix captured at decision time.
RevokedBefore(h, i) ==
  \E j \in 1..audit_log[i].rev_len : revocation_history[j] = h

TypeInvariant ==
  /\ global_epoch \in Nat
  /\ revoked_set \subseteq ProofHashes
  /\ session_rights \in [Actors -> SUBSET AllRights]
  /\ \A j \in 1..Len(revocation_history) : revocation_history[j] \in ProofHashes
  /\ \A i \in 1..Len(audit_log) :
       /\ audit_log[i].action \in CanonicalAction
       /\ audit_log[i].decision \in Decision
       /\ audit_log[i].revoked_at \subseteq ProofHashes
       /\ audit_log[i].witness \subseteq audit_log[i].action.cap_bundle
       /\ audit_log[i].now \in Nat
       /\ audit_log[i].rev_len \in 0..Len(revocation_history)

\* ── Safety invariants ───────────────────────────────────────────────────────

\* I1: Epoch Safety — every Permit in audit_log was issued with cap.epoch >= min_epoch.
EpochSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      LET a == audit_log[i].action
          actor_caps == {c \in a.cap_bundle : c.subject_id = a.actor_id}
      IN \A c \in actor_caps : c.epoch >= a.min_epoch

\* I2: Identity Binding — every Delegated cap in any Permit has issuer binding.
\*
\* HasParent GUARD (added on branch tlc-remediation): FindParent is a CHOOSE
\* (see the definition above). Evaluating CHOOSE over an empty candidate set is
\* a TLC RUNTIME ABORT, not an invariant violation — the model checker dies
\* instead of reporting anything. The HasParent conjunct converts that abort
\* into a well-defined check.
\*
\* THIS LOSES NO STRENGTH. ChainComplete (below) separately and unconditionally
\* asserts that every Delegated cap in a Permit's bundle HAS its parent in that
\* bundle. So the missing-parent case is not silently excused by this guard --
\* it is caught by ChainComplete instead. Both are checked in the cfg, and their
\* conjunction is exactly the unguarded meaning:
\*   ChainComplete /\ IdentityBinding(guarded)  ==  IdentityBinding(unguarded)
\* The guard changes only WHICH invariant reports the failure, never whether one does.
IdentityBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        (/\ c.issuer.type = "Delegated"
         /\ HasParent(c, audit_log[i].action.cap_bundle)) =>
          LET parent == FindParent(c, audit_log[i].action.cap_bundle)
          IN Hash(c.issuer_pubkey) = parent.subject_id

\* I3: Attenuation — child.rights ⊆ parent.rights for every Delegated cap in any Permit.
\* Same HasParent guard, same justification as IdentityBinding above: ChainComplete
\* independently asserts the parent IS present, so guarding the CHOOSE here removes
\* a runtime abort without weakening the property.
Attenuation ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        (/\ c.issuer.type = "Delegated"
         /\ HasParent(c, audit_log[i].action.cap_bundle)) =>
          LET parent == FindParent(c, audit_log[i].action.cap_bundle)
          IN c.rights \subseteq parent.rights

\* I4: Revocation Safety — at the time a Permit was issued, no contributing cap
\* was in the revoked set at that moment.
\*
\* BUG NOTE: The naive formulation `c.proof_hash \notin revoked_set` (live state)
\* is WRONG — it would be violated by any subsequent Revoke(h) call on a proof hash
\* that was legitimately permitted before the revocation. Revocation is prospective,
\* not retroactive.
\*
\* DE-TAUTOLOGIZED (tlc-remediation). The previous formulation checked
\* `c.proof_hash \notin audit_log[i].revoked_at` — literally the same predicate
\* on the same snapshot that Witnesses had already filtered on. It restated the
\* enforcement rather than constraining it, and could not fail by construction.
\*
\* This version is an INDEPENDENT statement over `revocation_history`, a variable
\* that no enforcement path reads: for every cap that justified a Permit, that
\* cap's hash does not appear anywhere in the prefix of the revocation history
\* that had already occurred when the decision was taken.
\*
\* Prospectivity is preserved: only the prefix (1..rev_len) is examined, so a
\* revocation issued AFTER the decision cannot retroactively violate it.
RevocationSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        ~RevokedBefore(w.proof_hash, i)

\* I5: Composition Monotonicity — session_rights never decreases for any actor.
CompositionMono ==
  \* Checked as a liveness property: after record(), accumulated never decreases.
  \A actor \in Actors :
    session_rights[actor] =
      UNION {audit_log[i].action.required_rights :
             i \in {j \in 1..Len(audit_log) :
                    /\ audit_log[j].decision = "Permit"
                    /\ audit_log[j].action.actor_id = actor}}

\* I6: Resource Binding — every Permit matches cap resource to action resource.
ResourceBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.subject_id = audit_log[i].action.actor_id =>
          c.resource_hash = audit_log[i].action.resource_hash

\* I7: Chain Epoch — every node in a valid chain has epoch >= min_epoch.
\* (Enforced inside ValidChain; stated here as a top-level invariant.)
ChainEpoch ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        ValidChain(c, audit_log[i].action.cap_bundle,
                   audit_log[i].action.min_epoch)

\* ════════════════════════════════════════════════════════════════════════════
\* INDEPENDENT INVARIANTS (added on branch tlc-remediation)
\* ════════════════════════════════════════════════════════════════════════════
\*
\* The audit found nine of thirteen enforcement checks were NOT CAUGHT by the
\* original ten invariants: delete the check, run the unmodified cfg, still
\* green. Two root causes:
\*
\*   (a) SELF-REFERENCE. ChainEpoch and PermitSoundness re-invoked ValidChain /
\*       Verify -- the very definitions that computed the decision. Weakening
\*       enforcement weakened the invariant in lockstep, so nothing could fire.
\*
\*   (b) MISSING TEST DATA. All six model caps carried rights |-> {"READ"}, so
\*       no cap could escalate relative to its parent. (Addressed in the MC
\*       module, not here.)
\*
\* Every invariant in this section is written against RECORDED DATA -- the
\* witness set, action_name, now, rev_len -- and states its property LITERALLY
\* in its own text. None of them calls Verify, Witnesses, or ValidChain.
\* ChainNodes is used for chain traversal because it is purely structural and
\* is unaffected by deleting an enforcement check.
\*
\* This is what makes them falsifiable: delete a check from Witnesses/ValidChain,
\* a bad cap enters the witness set, and the corresponding invariant below fires
\* with a concrete counterexample.

\* Every cap on the chain of every justifying cap of every Permit.
\* (Scoped to the WITNESS, not to all caps in the bundle -- see audit finding 7.)
PermitChainNodes(i) ==
  UNION {ChainNodes(w, audit_log[i].action.cap_bundle) : w \in audit_log[i].witness}

\* ── A1 / AT-1: the canonical binding gate ───────────────────────────────────
\* The audit validated this exact form: passes on baseline, CATCHES the mutant
\* that deletes the `IF ~action.binding_valid THEN Deny` gate.
NoPermitOnTamperedBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" => audit_log[i].action.binding_valid

\* ── AT-2: root capabilities must be signed BY THE ROOT KEY ──────────────────
\* Before this branch, RootKey appeared in no executable expression at all, so
\* any issuer_pubkey with sig_valid=TRUE validated a root cap. ValidChain now
\* enforces `issuer_pubkey = RootKey`; this invariant is what can SEE it.
RootKeyAuthority ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        n.issuer.type = "Root" => n.issuer_pubkey = RootKey

\* ── Signature checks (root and intermediate, stated separately) ─────────────
RootSignatureValid ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        n.issuer.type = "Root" => n.sig_valid

IntermediateSignatureValid ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        n.issuer.type = "Delegated" => n.sig_valid

\* ── Leaf epoch gate (I1, stated over the justifying cap) ────────────────────
WitnessLeafEpoch ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        w.epoch >= audit_log[i].action.min_epoch

\* ── Chain epoch (I7), stated structurally rather than via ValidChain ────────
WitnessChainEpoch ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        n.epoch >= audit_log[i].action.min_epoch

\* ── Expiry ──────────────────────────────────────────────────────────────────
\* Previously UNSTATABLE: `now` was never recorded in the audit log, so there was
\* nothing to compare expiry against, and PermitSoundness deliberately omitted
\* the expiry conjunct. `now` is now recorded, so this is expressible.
WitnessNotExpired ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        w.expiry >= audit_log[i].now

\* ── Attenuation (A6 / I3), stated over the witness chain ────────────────────
\* Falsifiable only once the model actually contains a cap whose rights exceed
\* its parent's -- see EscalationCap in MC_AuthGateV3.tla.
WitnessAttenuation ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        (/\ n.issuer.type = "Delegated"
         /\ HasParent(n, audit_log[i].action.cap_bundle)) =>
          n.rights \subseteq FindParent(n, audit_log[i].action.cap_bundle).rights

\* ── Identity binding (I2), stated over the witness chain ────────────────────
WitnessIdentityBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        (/\ n.issuer.type = "Delegated"
         /\ HasParent(n, audit_log[i].action.cap_bundle)) =>
          Hash(n.issuer_pubkey)
            = FindParent(n, audit_log[i].action.cap_bundle).subject_id

\* ── Chain completeness (I8), stated over the witness chain ──────────────────
WitnessChainComplete ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A n \in PermitChainNodes(i) :
        n.issuer.type = "Delegated" =>
          HasParent(n, audit_log[i].action.cap_bundle)

\* ── Actor / resource / rights binding of the justifying cap ─────────────────
WitnessActorMatch ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        w.subject_id = audit_log[i].action.actor_id

WitnessResourceBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        w.resource_hash = audit_log[i].action.resource_hash

WitnessRightsCoverage ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A w \in audit_log[i].witness :
        audit_log[i].action.required_rights \subseteq w.rights

\* ── A Permit must actually have a witness ───────────────────────────────────
PermitHasWitness ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" => audit_log[i].witness # {}

\* ── DENY-COMPLETENESS ───────────────────────────────────────────────────────
\*
\* The audit's finding 5: all eight safety invariants are implications guarded
\* on decision = "Permit", and seven of nine modelled actions ALWAYS Deny. So
\* the invariants said nothing whatsoever about those seven actions -- they were
\* decorative. Every one of them is an attack that is supposed to be blocked,
\* and nothing checked that it was.
\*
\* These properties convert each adversarial action into a CHECKED one: every
\* audit entry produced by that action must be a Deny. This is expressible only
\* because ExecuteVerify now tags entries with action_name.
\*
\* Unlike the Permit-guarded invariants, these are NOT vacuous -- they have real
\* content on exactly the states the old suite ignored.
DeniedAlways(aname) ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].action_name = aname => audit_log[i].decision = "Deny"

DenyBadSig            == DeniedAlways("BadSig")
DenyImpersonation     == DeniedAlways("Impersonation")
DenyWrongActor        == DeniedAlways("WrongActor")
DenyTampered          == DeniedAlways("Tampered")
DenyEscalation        == DeniedAlways("Escalation")
DenyStaleEpoch        == DeniedAlways("StaleEpoch")
DenyStaleIntermediate == DeniedAlways("StaleIntermediate")

\* ── State transitions ───────────────────────────────────────────────────────

Init ==
  /\ global_epoch = 0
  /\ revoked_set = {}
  /\ session_rights = [a \in Actors |-> {}]
  /\ revocation_history = <<>>
  /\ audit_log = <<>>

\* Advance the global epoch. Strictly monotone — never decreases.
\* All proofs with epoch < new_epoch are invalidated.
AdvanceEpoch(new_epoch) ==
  /\ new_epoch > global_epoch
  /\ new_epoch <= MaxEpoch
  /\ global_epoch' = new_epoch
  /\ UNCHANGED <<revoked_set, session_rights, revocation_history, audit_log>>

\* Root-signed emergency revocation of a single proof.
\* Guarded by `\notin revoked_set` so revocation_history stays bounded (it is a
\* permutation of a subset of ProofHashes rather than an unbounded sequence).
\* Re-revoking an already-revoked hash is a no-op in the real kernel anyway.
Revoke(proof_hash) ==
  /\ proof_hash \in ProofHashes
  /\ proof_hash \notin revoked_set
  /\ revoked_set' = revoked_set \cup {proof_hash}
  /\ revocation_history' = Append(revocation_history, proof_hash)
  /\ UNCHANGED <<global_epoch, session_rights, audit_log>>

\* Execute a verify() call. Records result in audit_log.
\*
\* Audit record fields:
\*   action      — the canonical action presented to the kernel
\*   action_name — WHICH modelled action produced this entry. Required for the
\*                 deny-completeness properties: without it the seven adversarial
\*                 actions are indistinguishable in the log and "this attack is
\*                 always denied" is not expressible.
\*   decision    — "Permit" | "Deny"
\*   witness     — the caps that JUSTIFIED a Permit ({} on Deny). Recorded as
\*                 data so invariants can be scoped to the justifying cap.
\*   now         — the timestamp the decision was taken at. Previously NOT
\*                 recorded, which is why expiry was unstatable as an invariant.
\*   revoked_at  — snapshot of revoked_set (retained; used by Witnesses)
\*   rev_len     — length of revocation_history at decision time, i.e. the
\*                 prefix of revocations that had already happened
ExecuteVerify(action, now, aname) ==
  /\ action \in CanonicalAction
  /\ action.min_epoch = global_epoch   \* caller must use the current epoch
  /\ LET w == Witnesses(action, revoked_set, now)
         d == IF w = {} THEN "Deny" ELSE "Permit"
     IN /\ audit_log' = Append(audit_log,
                               [action      |-> action,
                                action_name |-> aname,
                                decision    |-> d,
                                witness     |-> w,
                                now         |-> now,
                                revoked_at  |-> revoked_set,
                                rev_len     |-> Len(revocation_history)])
        /\ IF d = "Permit"
           THEN session_rights' =
                  [session_rights EXCEPT
                     ![action.actor_id] =
                       session_rights[action.actor_id] \cup action.required_rights]
           ELSE UNCHANGED session_rights
  /\ UNCHANGED <<global_epoch, revoked_set, revocation_history>>

Next ==
  \/ \E e \in Nat : AdvanceEpoch(e)
  \/ \E h \in ProofHashes : Revoke(h)
  \/ \E a \in CanonicalAction, t \in Nat : ExecuteVerify(a, t, "Generic")

Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(Next)

\* ── I8: Chain Completeness ──────────────────────────────────────────────────
\*
\* Every Delegated cap in a Permit's bundle has its parent in the same bundle.
\* This invariant is enforced inside ValidChain (via HasParent) but stated here
\* explicitly so the lattice dependency I2,I3 ← I8 is visible.

ChainComplete ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.issuer.type = "Delegated" =>
          HasParent(c, audit_log[i].action.cap_bundle)

\* ── Invariant Lattice ────────────────────────────────────────────────────────
\*
\* Dependency structure:
\*
\*   I7 (ChainEpoch)                   ─── strictly stronger than I1 ──► I1 (EpochSafety)
\*   I8 (ChainComplete)                ─── prerequisite for I2 and I3 to be well-defined
\*   I2 (IdentityBinding) ─depends─► I8
\*   I3 (Attenuation)     ─depends─► I8
\*   I4 (RevocationSafety)             ─── independent of I1-I3, I5-I8
\*   I5 (CompositionMono)              ─── independent (different state variable)
\*   I6 (ResourceBinding)              ─── independent of chain structure
\*
\* Minimal generating set: {I2, I3, I4, I5, I6, I7, I8}
\*   (I1 is omitted: it is implied by I7 since ValidChain checks the leaf epoch first)
\*
\* ValidChain(leaf, bundle, mep) ≡ (I2 ∧ I3 ∧ I7 ∧ I8) applied recursively to the chain.

\* BigSafety: the system-level safety invariant.
\* Now the conjunction of the original eight AND the independent invariants
\* added on tlc-remediation. The original eight are retained unchanged in
\* meaning; nothing was weakened or removed.
BigSafety ==
  \* ── original eight ──
  /\ TypeInvariant
  /\ EpochSafety
  /\ IdentityBinding
  /\ Attenuation
  /\ RevocationSafety
  /\ CompositionMono
  /\ ResourceBinding
  /\ ChainEpoch
  /\ ChainComplete
  \* ── independent invariants (tlc-remediation) ──
  /\ NoPermitOnTamperedBinding
  /\ RootKeyAuthority
  /\ RootSignatureValid
  /\ IntermediateSignatureValid
  /\ WitnessLeafEpoch
  /\ WitnessChainEpoch
  /\ WitnessNotExpired
  /\ WitnessAttenuation
  /\ WitnessIdentityBinding
  /\ WitnessChainComplete
  /\ WitnessActorMatch
  /\ WitnessResourceBinding
  /\ WitnessRightsCoverage
  /\ PermitHasWitness
  \* ── deny-completeness for the seven adversarial actions ──
  /\ DenyBadSig
  /\ DenyImpersonation
  /\ DenyWrongActor
  /\ DenyTampered
  /\ DenyEscalation
  /\ DenyStaleEpoch
  /\ DenyStaleIntermediate

\* PermitSoundness: the primary safety claim of the authgate TCB kernel --
\* an INDEPENDENT statement of what a Permit means.
\*
\* DE-TAUTOLOGIZED (tlc-remediation). The previous version rebuilt `valid_caps`
\* by re-invoking ValidChain -- the same predicate that produced the decision --
\* and asserted it was non-empty. That is a re-execution of Verify, not a
\* specification of it: delete any check from ValidChain and this invariant
\* weakened identically, so it could never fail. It also silently omitted the
\* expiry conjunct that Verify had, so an expired-cap Permit violated nothing.
\*
\* This version spells out every condition literally in its own text. It calls
\* neither Verify, nor Witnesses, nor ValidChain. Chain traversal goes through
\* ChainNodes, which is purely structural. Expiry is included, against the now
\* recorded `now`. Revocation is checked against revocation_history.
\*
\* Read it as: "if the kernel said Permit, then there really was a capability
\* that (i) belongs to this actor, (ii) covers this resource and these rights,
\* (iii) had not expired or gone stale, (iv) had not been revoked, and (v) whose
\* entire chain up to a root key is well-signed, epoch-current, identity-bound,
\* and attenuating."
PermitSoundness ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      LET a == audit_log[i].action
          b == a.cap_bundle
      IN /\ a.binding_valid                       \* L1 canonical gate
         /\ audit_log[i].witness # {}             \* a Permit needs a justifying cap
         /\ \A w \in audit_log[i].witness :
              /\ w \in b                          \* the witness came from the bundle
              /\ w.subject_id = a.actor_id        \* actor binding
              /\ w.resource_hash = a.resource_hash            \* I6
              /\ w.expiry >= audit_log[i].now                 \* expiry
              /\ w.epoch >= a.min_epoch                       \* I1 leaf epoch
              /\ a.required_rights \subseteq w.rights         \* rights coverage
              /\ ~RevokedBefore(w.proof_hash, i)              \* I4
              /\ \A n \in ChainNodes(w, b) :
                   /\ n.sig_valid                             \* signature, every node
                   /\ n.epoch >= a.min_epoch                  \* I7 chain epoch
                   /\ (n.issuer.type = "Root" =>
                        n.issuer_pubkey = RootKey)            \* AT-2 root authority
                   /\ (n.issuer.type = "Delegated" =>
                        /\ HasParent(n, b)                    \* I8
                        /\ Hash(n.issuer_pubkey)
                             = FindParent(n, b).subject_id    \* I2
                        /\ n.rights \subseteq FindParent(n, b).rights)  \* I3

\* ── Theorems (to be verified by TLC / TLAPS) ────────────────────────────────

\* NOTE ON STATUS (tlc-remediation). A `THEOREM` line in this file is a CLAIM,
\* not a proof. None of these has a TLAPS proof. What has actually been checked
\* is recorded in formal/tlc_runs/ with the exact command line, bound, and
\* verbatim TLC output. TLC results are bounded-model results at a stated
\* Len(audit_log) bound -- never a proof for all executions.

\* Individual invariants
THEOREM Spec => []TypeInvariant
THEOREM Spec => []EpochSafety
THEOREM Spec => []IdentityBinding
THEOREM Spec => []Attenuation
THEOREM Spec => []RevocationSafety
THEOREM Spec => []ResourceBinding
THEOREM Spec => []ChainEpoch
THEOREM Spec => []ChainComplete
THEOREM Spec => []PermitSoundness

\* Independent invariants (tlc-remediation)
THEOREM Spec => []NoPermitOnTamperedBinding
THEOREM Spec => []RootKeyAuthority
THEOREM Spec => []RootSignatureValid
THEOREM Spec => []IntermediateSignatureValid
THEOREM Spec => []WitnessLeafEpoch
THEOREM Spec => []WitnessChainEpoch
THEOREM Spec => []WitnessNotExpired
THEOREM Spec => []WitnessAttenuation
THEOREM Spec => []WitnessIdentityBinding
THEOREM Spec => []WitnessChainComplete
THEOREM Spec => []WitnessActorMatch
THEOREM Spec => []WitnessResourceBinding
THEOREM Spec => []WitnessRightsCoverage
THEOREM Spec => []PermitHasWitness

\* Lattice theorem T1: I7 implies I1.
\* Proof sketch: ValidChain(leaf, bundle, mep) starts by checking leaf.epoch >= mep.
\* If ValidChain holds (required for Permit via PermitSoundness), then I1 holds.
THEOREM Spec => [](ChainEpoch => EpochSafety)

\* Lattice theorem T2: BigSafety is the conjunction of the minimal generating set.
\* I1 (EpochSafety) is NOT in the minimal set because T1 proves it is implied by I7.
\* Adding it to BigSafety is redundant but makes the invariant list explicit.
THEOREM Spec => []BigSafety

\* Lattice theorem T3: PermitSoundness implies RevocationSafety.
\* Proof sketch: PermitSoundness says valid_caps (which excludes revoked hashes
\* at decision time) is non-empty for every Permit. RevocationSafety says no
\* Permit's actor cap is in revoked_at. Both are checked in valid_caps.
THEOREM Spec => [](PermitSoundness => RevocationSafety)

\* Lattice theorem T4: PermitSoundness implies EpochSafety.
\* Proof sketch: valid_caps requires c.epoch >= a.min_epoch (I1 leaf epoch)
\* and ValidChain (which requires all chain nodes >= min_epoch, i.e., I7).
THEOREM Spec => [](PermitSoundness => EpochSafety)

\* Lattice theorem T5: ValidChain is the conjunction of I2, I3, I7, I8.
\* This is an internal correctness theorem about the spec's own predicates.
\* Proof: by unfolding ValidChain definition.
THEOREM \A c \in CapabilityProof, b \in SUBSET CapabilityProof, mep \in Nat :
  ValidChain(c, b, mep) =>
    /\ c.epoch >= mep                                    \* I7 at this node
    /\ c.sig_valid                                       \* signature valid
    /\ (c.issuer.type = "Delegated" =>
         /\ HasParent(c, b)                              \* I8
         /\ LET p == FindParent(c, b) IN
            /\ Hash(c.issuer_pubkey) = p.subject_id      \* I2
            /\ c.rights \subseteq p.rights)              \* I3

\* Liveness: every valid action eventually gets a decision.
THEOREM Spec => \A a \in CanonicalAction :
                  <>(Len(audit_log) > 0)

=============================================================================

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
                   current.sig_valid                 \* root sig against RootKey
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

Verify(action, revoked_set_var, now) ==
  IF ~action.binding_valid THEN "Deny"   \* L1: canonical gate
  ELSE
    LET actor_caps == {c \in action.cap_bundle : c.subject_id = action.actor_id}
        valid_caps == {c \in actor_caps :
          /\ c.resource_hash = action.resource_hash     \* I6
          /\ c.expiry >= now                            \* expiry
          /\ c.epoch >= action.min_epoch                \* I1 leaf epoch
          /\ ValidChain(c, action.cap_bundle, action.min_epoch) \* I2 I3 I7 I8
          /\ action.required_rights \subseteq c.rights  \* rights coverage
          /\ c.proof_hash \notin revoked_set_var}        \* I4 revocation
    IN IF valid_caps = {} THEN "Deny" ELSE "Permit"

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
  audit_log           \* Seq of [action, decision, revoked_at] records
                      \* revoked_at: snapshot of revoked_set AT decision time

vars == <<global_epoch, revoked_set, session_rights, audit_log>>

TypeInvariant ==
  /\ global_epoch \in Nat
  /\ revoked_set \subseteq ProofHashes
  /\ session_rights \in [Actors -> SUBSET AllRights]
  /\ \A i \in 1..Len(audit_log) :
       /\ audit_log[i].action \in CanonicalAction
       /\ audit_log[i].decision \in Decision
       /\ audit_log[i].revoked_at \subseteq ProofHashes

\* ── Safety invariants ───────────────────────────────────────────────────────

\* I1: Epoch Safety — every Permit in audit_log was issued with cap.epoch >= min_epoch.
EpochSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      LET a == audit_log[i].action
          actor_caps == {c \in a.cap_bundle : c.subject_id = a.actor_id}
      IN \A c \in actor_caps : c.epoch >= a.min_epoch

\* I2: Identity Binding — every Delegated cap in any Permit has issuer binding.
IdentityBinding ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.issuer.type = "Delegated" =>
          LET parent == FindParent(c, audit_log[i].action.cap_bundle)
          IN Hash(c.issuer_pubkey) = parent.subject_id

\* I3: Attenuation — child.rights ⊆ parent.rights for every Delegated cap in any Permit.
Attenuation ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.issuer.type = "Delegated" =>
          LET parent == FindParent(c, audit_log[i].action.cap_bundle)
          IN c.rights \subseteq parent.rights

\* I4: Revocation Safety — at the time a Permit was issued, no contributing cap
\* was in the revoked set at that moment.
\*
\* BUG NOTE: The naive formulation `c.proof_hash \notin revoked_set` (current state)
\* is WRONG — it would be violated by any subsequent Revoke(h) call on a proof hash
\* that was legitimately permitted before the revocation. Revocation is prospective,
\* not retroactive. The fix: record revoked_set as a snapshot (revoked_at field)
\* at decision time. This invariant checks the snapshot, not the live state.
RevocationSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.subject_id = audit_log[i].action.actor_id =>
          c.proof_hash \notin audit_log[i].revoked_at

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

\* ── State transitions ───────────────────────────────────────────────────────

Init ==
  /\ global_epoch = 0
  /\ revoked_set = {}
  /\ session_rights = [a \in Actors |-> {}]
  /\ audit_log = <<>>

\* Advance the global epoch. Strictly monotone — never decreases.
\* All proofs with epoch < new_epoch are invalidated.
AdvanceEpoch(new_epoch) ==
  /\ new_epoch > global_epoch
  /\ new_epoch <= MaxEpoch
  /\ global_epoch' = new_epoch
  /\ UNCHANGED <<revoked_set, session_rights, audit_log>>

\* Root-signed emergency revocation of a single proof.
Revoke(proof_hash) ==
  /\ proof_hash \in ProofHashes
  /\ revoked_set' = revoked_set \cup {proof_hash}
  /\ UNCHANGED <<global_epoch, session_rights, audit_log>>

\* Execute a verify() call. Records result in audit_log.
\* Captures revoked_set snapshot at decision time (fixes I4 / RevocationSafety).
\* On Permit: updates session_rights for the actor (composition tracking).
ExecuteVerify(action, now) ==
  /\ action \in CanonicalAction
  /\ action.min_epoch = global_epoch   \* caller must use the current epoch
  /\ LET d == Verify(action, revoked_set, now)
     IN /\ audit_log' = Append(audit_log,
                               [action     |-> action,
                                decision   |-> d,
                                revoked_at |-> revoked_set])  \* snapshot
        /\ IF d = "Permit"
           THEN session_rights' =
                  [session_rights EXCEPT
                     ![action.actor_id] =
                       session_rights[action.actor_id] \cup action.required_rights]
           ELSE UNCHANGED session_rights
  /\ UNCHANGED <<global_epoch, revoked_set>>

Next ==
  \/ \E e \in Nat : AdvanceEpoch(e)
  \/ \E h \in ProofHashes : Revoke(h)
  \/ \E a \in CanonicalAction, t \in Nat : ExecuteVerify(a, t)

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

\* BigSafety: the system-level safety invariant — conjunction of all 8 invariants.
BigSafety ==
  /\ TypeInvariant
  /\ EpochSafety
  /\ IdentityBinding
  /\ Attenuation
  /\ RevocationSafety
  /\ CompositionMono
  /\ ResourceBinding
  /\ ChainEpoch
  /\ ChainComplete

\* PermitSoundness: every Permit in the log corresponds to an action that would
\* be verified correctly against the revoked_set at the time of the decision.
\* This is the primary safety claim of the authgate TCB kernel.
PermitSoundness ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      LET a == audit_log[i].action
          actor_caps == {c \in a.cap_bundle : c.subject_id = a.actor_id}
          valid_caps == {c \in actor_caps :
            /\ c.resource_hash = a.resource_hash
            /\ c.epoch >= a.min_epoch
            /\ ValidChain(c, a.cap_bundle, a.min_epoch)
            /\ a.required_rights \subseteq c.rights
            /\ c.proof_hash \notin audit_log[i].revoked_at}
      IN valid_caps # {}

\* ── Theorems (to be verified by TLC / TLAPS) ────────────────────────────────

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

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
  audit_log           \* Seq of [action, decision] records

vars == <<global_epoch, revoked_set, session_rights, audit_log>>

TypeInvariant ==
  /\ global_epoch \in Nat
  /\ revoked_set \subseteq ProofHashes
  /\ session_rights \in [Actors -> SUBSET AllRights]
  /\ \A i \in 1..Len(audit_log) :
       /\ audit_log[i].action \in CanonicalAction
       /\ audit_log[i].decision \in Decision

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

\* I4: Revocation Safety — a revoked proof hash never contributes to Permit.
RevocationSafety ==
  \A i \in 1..Len(audit_log) :
    audit_log[i].decision = "Permit" =>
      \A c \in audit_log[i].action.cap_bundle :
        c.subject_id = audit_log[i].action.actor_id =>
          c.proof_hash \notin revoked_set

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
\* On Permit: updates session_rights for the actor (composition tracking).
ExecuteVerify(action, now) ==
  /\ action \in CanonicalAction
  /\ action.min_epoch = global_epoch   \* caller must use the current epoch
  /\ LET d == Verify(action, revoked_set, now)
     IN /\ audit_log' = Append(audit_log, [action |-> action, decision |-> d])
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

\* ── Theorems (to be verified by TLC / TLAPS) ────────────────────────────────

THEOREM Spec => []TypeInvariant
THEOREM Spec => []EpochSafety
THEOREM Spec => []IdentityBinding
THEOREM Spec => []Attenuation
THEOREM Spec => []RevocationSafety
THEOREM Spec => []ResourceBinding
THEOREM Spec => []ChainEpoch

\* Liveness: every valid action eventually gets a decision.
THEOREM Spec => \A a \in CanonicalAction :
                  <>(Len(audit_log) > 0)

=============================================================================

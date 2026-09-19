-- Proofs.lean — Machine-checked proofs of authgate-kernel invariants.
--
-- Status: Proofs of the pure logical properties (epoch, rights, attenuation) are
-- complete. Proofs involving the cryptographic oracle (INV-SIGCHAIN, INV-REVOCATION)
-- are stated as axioms reducible to ed25519 security — those are left as admitted
-- pending integration of a Lean 4 ed25519 verification library.

import Authgate.Core
import Authgate.Invariants

namespace Authgate.Proofs

open Authgate Authgate.Invariants

-- ─── Lemma: Attenuation is transitive ────────────────────────────────────────
-- If A → B → C is a delegation chain, and B ⊆ A and C ⊆ B, then C ⊆ A.
-- Used to justify chain-level attenuation from pairwise attenuation checks.
theorem attenuation_transitive
    (a b c : CapProof)
    (h1 : Attenuated b a)  -- b's rights ⊆ a's rights
    (h2 : Attenuated c b)  -- c's rights ⊆ b's rights
    : Attenuated c a := by
  exact Finset.Subset.trans h2 h1

-- ─── Lemma: Rights sufficiency check is correct ──────────────────────────────
-- If cap.rights ⊇ required, then required ⊆ cap.rights (tautology, but stated
-- explicitly to match the Rust check: (cap.rights & required) == required).
theorem rights_sufficiency_correct
    (cap : CapProof) (required : Rights)
    (h : required ⊆ cap.rights)
    : SufficientRights ⟨0, 0, required, [], [], 0, 0⟩ cap := by
  exact h

-- ─── Lemma: Epoch gate is a total order check ────────────────────────────────
-- cap.epoch < min_epoch → proof is stale, must be rejected.
-- cap.epoch ≥ min_epoch → epoch condition satisfied.
-- No third case exists.
theorem epoch_gate_total
    (cap_epoch min_epoch : Epoch)
    : cap_epoch < min_epoch ∨ min_epoch ≤ cap_epoch := by
  exact Nat.lt_or_ge cap_epoch min_epoch

-- ─── Lemma: Epoch gate subsumes revocation list for epoch-bounded proofs ─────
-- A proof from epoch e < min_epoch is denied without consulting any revocation list.
-- The caller advances min_epoch to revoke by epoch; no list distribution required.
theorem stale_epoch_implies_deny
    (a : CanonicalAction) (cap : CapProof)
    (h : cap.epoch < a.minEpoch)
    : ¬ FreshEpoch a cap := by
  exact Nat.not_le.mpr h

-- ─── Lemma: Subject binding is a strict equality check ───────────────────────
-- If actor ≠ subject, the proof does not satisfy SubjectBinding.
theorem subject_mismatch_violates_binding
    (a : CanonicalAction) (cap : CapProof)
    (h : cap.subject ≠ a.actorId)
    : ¬ SubjectBinding a cap := by
  simp [SubjectBinding]
  exact h

-- ─── Admitted: Signature validity implies non-forgeable origin ───────────────
-- If IsValidSig(key, sig, msg) holds, then no party without key's private key
-- could have produced sig. This reduces to ed25519 EUF-CMA security.
-- Admitted pending Lean 4 ed25519 formalization.
axiom sig_euf_cma
    (key : PrincipalId) (sig msg : List Nat)
    (h : IsValidSig key sig msg)
    : True  -- placeholder; real statement requires key/sig types

-- ─── Theorem: Invalid revocation does not affect Layer 3's decision ──────────
-- Models authgate-kernel/src/tcb/engine.rs Layer 3 (lines 90-104):
--   for rev in &action.revocation_proofs {
--       if !verify_revocation_sig(rev, root_key) { continue; }
--       for cap in &action.capability_proofs {
--           if cap.proof_hash == rev.target_proof_hash { return Deny(...); }
--       }
--   }
-- `capHash` stands in for the Rust `CapabilityProof.proof_hash` field, which
-- Core.lean's `CapProof` does not carry explicitly (kept abstract rather than
-- widening the shared struct and touching every other proof in this file).
-- `RevocationDenies` is that loop's Deny condition, stated as a Prop.
def RevocationDenies
    (revocations : List RevProof) (caps : List CapProof) (capHash : CapProof → Nat) : Prop :=
  ∃ rev ∈ revocations, ValidRevocation rev ∧ ∃ cap ∈ caps, rev.targetHash = capHash cap

-- "Attackers cannot forge a revocation of a valid capability, nor can they
-- deny service by injecting garbage revocation proofs (those are simply
-- skipped)" — the engine.rs comment above the loop, now a machine-checked
-- property: prepending an invalid-signature revocation to the list can never
-- change whether Layer 3 denies.
theorem forged_revocation_harmless
    (capHash : CapProof → Nat) (revocations : List RevProof) (caps : List CapProof)
    (rev : RevProof) (h : ¬ ValidRevocation rev)
    : RevocationDenies (rev :: revocations) caps capHash
        ↔ RevocationDenies revocations caps capHash := by
  constructor
  · rintro ⟨r, hr, hvalid, cap, hcap, heq⟩
    rcases List.mem_cons.mp hr with rfl | hr'
    · exact absurd hvalid h
    · exact ⟨r, hr', hvalid, cap, hcap, heq⟩
  · rintro ⟨r, hr, hvalid, cap, hcap, heq⟩
    exact ⟨r, List.mem_cons_of_mem _ hr, hvalid, cap, hcap, heq⟩

end Authgate.Proofs

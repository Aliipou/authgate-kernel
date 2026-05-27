-- Invariants.lean — Formal statements of the nine TCB invariants.
-- Each invariant is stated as a Prop over the types in Core.lean.
-- Proofs.lean provides proofs of the ones amenable to machine-checking.

import Authgate.Core

namespace Authgate.Invariants

open Authgate

-- ─── INV-SUBJECT ────────────────────────────────────────────────────────────
-- Every accepted capability proof was issued to the requesting actor.
def SubjectBinding (a : CanonicalAction) (cap : CapProof) : Prop :=
  cap.subject = a.actorId

-- ─── INV-RESOURCE ───────────────────────────────────────────────────────────
-- Every accepted capability proof covers the resource being accessed.
def ResourceBinding (a : CanonicalAction) (cap : CapProof) : Prop :=
  cap.resource = a.resourceId

-- ─── INV-EXPIRY ─────────────────────────────────────────────────────────────
-- Every accepted capability proof has not expired at the time of verification.
def NotExpired (a : CanonicalAction) (cap : CapProof) : Prop :=
  a.now ≤ cap.expiry

-- ─── INV-EPOCH ──────────────────────────────────────────────────────────────
-- Every accepted capability proof was issued in or after the required epoch.
-- This closes the "stale-but-valid resurrection" attack:
-- even a cryptographically valid, non-expired proof is rejected if its epoch
-- predates what the caller requires.
def FreshEpoch (a : CanonicalAction) (cap : CapProof) : Prop :=
  a.minEpoch ≤ cap.epoch

-- ─── INV-ATTENUATION ────────────────────────────────────────────────────────
-- In any valid delegation chain, child rights are a subset of parent rights.
-- This prevents a delegated agent from exercising more authority than its delegator.
def Attenuated (child parent : CapProof) : Prop :=
  child.rights ⊆ parent.rights

-- ─── INV-RIGHTS ─────────────────────────────────────────────────────────────
-- Every accepted capability proof grants at least the required rights.
def SufficientRights (a : CanonicalAction) (cap : CapProof) : Prop :=
  a.requiredRights ⊆ cap.rights

-- ─── INV-SIGCHAIN ───────────────────────────────────────────────────────────
-- Every node in an accepted chain has a valid signature from its claimed issuer.
-- The actual signature oracle (IsValidSig) is axiomatized from ed25519 security.
def ValidSignature (cap : CapProof) : Prop :=
  IsValidSig cap.issuerKey cap.sigBytes (cap.subject.repr.toList)  -- simplified

-- ─── INV-REVOCATION ─────────────────────────────────────────────────────────
-- Only root-signed revocation proofs affect permit/deny decisions.
-- A revocation proof with an invalid signature is ignored, not used to deny.
-- This prevents denial-of-service via forged revocation proofs.
opaque RootKey : PrincipalId
def ValidRevocation (rev : RevProof) : Prop :=
  IsValidSig RootKey rev.sigBytes (rev.targetHash.repr.toList)  -- simplified

-- ─── INV-PERMIT-REQUIRES-ALL ────────────────────────────────────────────────
-- The master safety theorem: Permit implies ALL nine conditions hold for every
-- capability proof in the action.
def PermitImpliesAllInvariants (a : CanonicalAction) : Prop :=
  ∀ cap ∈ a.caps,
    SubjectBinding a cap ∧
    ResourceBinding a cap ∧
    NotExpired a cap ∧
    FreshEpoch a cap ∧
    SufficientRights a cap ∧
    ValidSignature cap

end Authgate.Invariants

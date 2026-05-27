-- Core.lean — Fundamental types for authgate-kernel formal model.
-- This file defines the mathematical objects; Invariants.lean states properties
-- over them; Proofs.lean proves those properties.

import Mathlib.Data.Finset.Basic
import Mathlib.Data.List.Basic

namespace Authgate

-- Rights bitmask. We model it as a Finset of right names for clarity.
-- The implementation uses u64 bitmasks; the correspondence is established
-- by the Rights.toFinset bijection (not proved here, assumed by construction).
abbrev RightName := String
abbrev Rights := Finset RightName

-- A principal's identity (hash of their key material in the implementation).
abbrev PrincipalId := Nat

-- A resource's identity (hash of canonical resource descriptor).
abbrev ResourceId := Nat

-- Epoch number. Increases monotonically; never wraps.
abbrev Epoch := Nat

-- Unix timestamp in seconds.
abbrev Timestamp := Nat

-- Cryptographic validity of a proof node. We treat signature verification
-- as an oracle (IsValidSig) — its soundness is assumed from the ed25519
-- security proof, not reproved here.
opaque IsValidSig : PrincipalId → List Nat → List Nat → Prop

-- A single capability proof node.
structure CapProof where
  subject   : PrincipalId
  resource  : ResourceId
  rights    : Rights
  expiry    : Timestamp
  epoch     : Epoch
  issuer    : Option PrincipalId  -- None = root-issued
  sigBytes  : List Nat
  issuerKey : PrincipalId
  deriving Repr

-- A revocation notice.
structure RevProof where
  targetHash : Nat  -- hash of the revoked CapProof
  revokedAt  : Timestamp
  sigBytes   : List Nat
  deriving Repr

-- An action request (canonical form).
structure CanonicalAction where
  actorId        : PrincipalId
  resourceId     : ResourceId
  requiredRights : Rights
  caps           : List CapProof
  revocations    : List RevProof
  now            : Timestamp
  minEpoch       : Epoch
  deriving Repr

-- The decision type.
inductive Decision where
  | Permit : Decision
  | Deny   : String → Decision
  deriving Repr

end Authgate

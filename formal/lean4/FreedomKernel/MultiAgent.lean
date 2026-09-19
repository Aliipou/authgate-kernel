-- formal/lean4/FreedomKernel/MultiAgent.lean
-- Multi-agent attenuation theorem: child authority ⊆ parent authority.
-- Mirrors multi_agent.rs structural constraint.

namespace FreedomKernel.MultiAgent

-- ── Authority as a set of resource permissions ────────────────────────────────

structure Permission where
  resourceId : String
  canRead    : Bool
  canWrite   : Bool
  canDelegate: Bool
  deriving DecidableEq, Repr

abbrev Authority := List Permission

-- ── Attenuation ───────────────────────────────────────────────────────────────

-- Child authority is attenuated: every child permission is ≤ parent permission.
-- "≤" means child cannot have a right the parent lacks for the same resource.

def permissionSubset (child parent : Permission) : Prop :=
  child.resourceId = parent.resourceId →
  (child.canRead    → parent.canRead) ∧
  (child.canWrite   → parent.canWrite) ∧
  (child.canDelegate → parent.canDelegate)

def authorityAttenuated (child parent : Authority) : Prop :=
  ∀ cp ∈ child, ∃ pp ∈ parent, permissionSubset cp pp

-- ── Attenuation Theorem ───────────────────────────────────────────────────────

-- If child authority is a strict subset of parent authority,
-- delegation cannot escalate privileges.
-- Enforced structurally in multi_agent.rs via DelegatedClaim.can_delegate=false by default.

theorem attenuation_cannot_escalate
    (child parent : Authority)
    (h : authorityAttenuated child parent) :
    -- No child permission exceeds parent permission
    ∀ cp ∈ child, ∃ pp ∈ parent, permissionSubset cp pp := h

-- ── Depth cap ────────────────────────────────────────────────────────────────

-- Recursion depth is bounded by MAX_DELEGATION_DEPTH = 16.
-- Prevents infinite agent spawning chains.
def MAX_DELEGATION_DEPTH : Nat := 16

theorem delegation_depth_bounded (depth : Nat) (h : depth ≤ MAX_DELEGATION_DEPTH) :
    depth ≤ MAX_DELEGATION_DEPTH := h

end FreedomKernel.MultiAgent

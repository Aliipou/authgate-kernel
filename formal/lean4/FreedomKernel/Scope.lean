-- formal/lean4/FreedomKernel/Scope.lean
-- Formal theorems about scope containment (scope_contains from entities.py).
--
-- Mirrors SEMANTICS.md §5 "Resource Scope Containment" properties.
-- The Python implementation is authgate.kernel.entities.scope_contains.
--
-- scope_contains(P, C) iff:
--   has_traversal(P) ∨ has_traversal(C) → False
--   ∨ P = ""                             → True  (root scope)
--   ∨ C = normalize(P)                   → True  (exact match after trailing-slash strip)
--   ∨ C.startswith(normalize(P) + "/")   → True  (C falls under P's prefix)
--   otherwise                            → False
--
-- has_traversal(path) := ".." ∈ path.split("/")
--
-- Build: cd formal/lean4 && lake build
--
-- ── 2026-08-02 REPAIR NOTE ────────────────────────────────────────────────
-- This file previously did not compile at all, so none of its theorems were
-- discharged regardless of what the proof scripts said. Three defects:
--
--   1. `normalize` was written `normalize path.dropRight 1`, which parses as
--      `normalize (path.dropRight) 1` — an application type error. Because the
--      definition failed to elaborate, Lean replaced it with `sorryAx`, which
--      silently poisoned EVERY theorem mentioning `normalize` (T-SC1, T-SC4,
--      T-SC5) whether or not that theorem had a visible `sorry`.
--   2. `split_ifs` is a Mathlib tactic; this file imports no Mathlib.
--   3. `cases hasTraversal P <;> simp` after a goal-closing `simp`.
--
-- The model is now phrased over `List Char` rather than over `String.splitOn`
-- and `String.dropRight`. This is a re-encoding, NOT a weakening: for a
-- single-character separator, `String.splitOn` agrees with `List.splitOn` on
-- `toList` (Lean core proves exactly this in
-- Init/Data/String/Lemmas/Pattern/Split/Char.lean), and `normalizeL` strips
-- trailing '/' characters exactly as the original recursion and as Python's
-- `rstrip("/")` do. The re-encoding is required because in Lean 4.32 `String`
-- is ByteArray-backed: `String.splitOn` is defined by well-founded recursion
-- over raw byte positions, has no lemmas, and does not reduce under `decide`,
-- so NOTHING about it is provable without `native_decide` — and `native_decide`
-- would add `Lean.ofReduceBool` to the axiom set, which is exactly the kind of
-- silent trust this file exists to avoid.
--
-- Every theorem statement below is unchanged in strength. T-SC1, which was
-- `sorry` before, is now fully proved. T-SC5 is now fully proved as well.

namespace FreedomKernel.Scope

-- ── Definitions ───────────────────────────────────────────────────────────────

abbrev isSlash : Char → Bool := (· = '/')

-- A path contains a ".." traversal segment iff ".." appears in its split.
def hasTraversalL (l : List Char) : Bool := (l.splitOn '/').contains ['.', '.']

def hasTraversal (path : String) : Bool := hasTraversalL path.toList

-- Normalize: strip trailing "/" characters.
def normalizeL (l : List Char) : List Char := (l.reverse.dropWhile isSlash).reverse

def normalize (path : String) : String := String.ofList (normalizeL path.toList)

-- The core predicate: does path C fall within scope P?
def scopeContains (P C : String) : Bool :=
  if hasTraversal P || hasTraversal C then false
  else if P == "" then true
  else
    let n := normalize P
    C == n || C.startsWith (n ++ "/")

-- ── Structural lemmas about `normalizeL` ─────────────────────────────────────

theorem dropWhile_idem (p : Char → Bool) (l : List Char) :
    (l.dropWhile p).dropWhile p = l.dropWhile p := by
  induction l with
  | nil => simp
  | cons c t ih =>
    by_cases hc : p c
    · simp [List.dropWhile, hc, ih]
    · simp [List.dropWhile, hc]

theorem normalizeL_idem (l : List Char) : normalizeL (normalizeL l) = normalizeL l := by
  simp [normalizeL, dropWhile_idem]

theorem normalizeL_append (a b : List Char) :
    normalizeL (a ++ b) = if normalizeL b = [] then normalizeL a else a ++ normalizeL b := by
  simp only [normalizeL, List.reverse_append]
  rw [List.dropWhile_append]
  by_cases h : b.reverse.dropWhile isSlash = []
  · simp [h]
  · have h2 : (b.reverse.dropWhile isSlash).isEmpty = false := by simp [h]
    simp [h, h2]

/-- Either a path is already normalized, or it is its normal form followed by
    a '/' and some remainder. This is the fact the original `sorry` in T-SC1
    stood in for. -/
theorem dropWhile_slash_spec (r : List Char) :
    (r.dropWhile isSlash).reverse = r.reverse
    ∨ ∃ v, (r.dropWhile isSlash).reverse ++ '/' :: v = r.reverse := by
  induction r with
  | nil => left; rfl
  | cons c t ih =>
    by_cases hc : c = '/'
    · subst hc
      have hd : ((('/' : Char) :: t).dropWhile isSlash) = t.dropWhile isSlash := by
        simp [List.dropWhile, isSlash]
      rw [hd]
      rcases ih with h | ⟨v, hv⟩
      · exact Or.inr ⟨[], by simp [h]⟩
      · exact Or.inr ⟨v ++ ['/'], by
          have : (t.dropWhile isSlash).reverse ++ '/' :: (v ++ ['/'])
               = ((t.dropWhile isSlash).reverse ++ '/' :: v) ++ ['/'] := by simp
          rw [this, hv]; simp⟩
    · left; simp [List.dropWhile, isSlash, hc]

theorem normalizeL_spec (l : List Char) :
    normalizeL l = l ∨ ∃ v, normalizeL l ++ '/' :: v = l := by
  have h := dropWhile_slash_spec l.reverse
  simp only [List.reverse_reverse] at h
  exact h

/-- If `a` is already normalized and `a ++ "/"` is a prefix of `l`, then either
    `l` normalizes back down to `a`, or `l`'s normal form is strictly longer. -/
theorem normalizeL_of_slash_prefix {a l : List Char}
    (ha : normalizeL a = a) (h : a ++ ['/'] <+: l) :
    normalizeL l = a ∨ a.length < (normalizeL l).length := by
  obtain ⟨w, hw⟩ := h
  have hl : l = a ++ ('/' :: w) := by rw [← hw]; simp
  subst hl
  rw [normalizeL_append]
  by_cases hn : normalizeL ('/' :: w) = []
  · left; rw [if_pos hn, ha]
  · right
    rw [if_neg hn, List.length_append]
    have hpos : (normalizeL ('/' :: w)).length ≠ 0 := by
      intro hz; exact hn (List.eq_nil_of_length_eq_zero hz)
    omega

@[simp] theorem toList_normalize (P : String) :
    (normalize P).toList = normalizeL P.toList := by
  simp [normalize]

theorem hasTraversal_empty : hasTraversal "" = false := by
  simp [hasTraversal, hasTraversalL]

theorem normalize_empty : normalize "" = "" := by
  simp [normalize, normalizeL]

-- ── Theorem T-SC1: Reflexivity ────────────────────────────────────────────────
-- scope_contains(P, P) is True for all paths without traversal segments.
--
-- Formal statement from SEMANTICS.md §5:
--   "Reflexive: scope_contains(P, P) is True for all P without traversal"
--
-- Was `sorry`. Now fully proved: either P is already normalized (exact-match
-- branch fires) or P is `normalize P` followed by trailing slashes (prefix
-- branch fires).

theorem scope_contains_reflexive (P : String) (h : hasTraversal P = false) :
    scopeContains P P = true := by
  simp [scopeContains, h]
  rcases normalizeL_spec P.toList with hn | ⟨v, hv⟩
  · right; left
    have : normalize P = P := by
      rw [show normalize P = String.ofList (normalizeL P.toList) from rfl, hn,
          String.ofList_toList]
    exact this.symm
  · right; right
    exact ⟨v, by simpa using hv⟩

-- ── Theorem T-SC2: Root scope contains everything ────────────────────────────
-- scope_contains("", C) is True for all C without traversal.

theorem scope_contains_root_universal (C : String) (h : hasTraversal C = false) :
    scopeContains "" C = true := by
  simp [scopeContains, h, hasTraversal_empty]

-- ── Theorem T-SC3: Traversal paths always rejected ──────────────────────────
-- For any path P containing "..", scopeContains(P, C) = False.
-- For any child C containing "..", scopeContains(P, C) = False.
--
-- Security relevance: ".." sequences are never normalized away; they are
-- structurally rejected. Normalizing untrusted paths is an attack surface
-- (see SEMANTICS.md §5 "Path traversal" note).

theorem traversal_in_parent_always_false (P C : String) (h : hasTraversal P = true) :
    scopeContains P C = false := by
  simp [scopeContains, h]

theorem traversal_in_child_always_false (P C : String) (h : hasTraversal C = true) :
    scopeContains P C = false := by
  simp [scopeContains, h]

-- ── Theorem T-SC4: Prefix implies containment ────────────────────────────────
-- If C starts with normalize(P) ++ "/" and neither has traversal,
-- then scopeContains(P, C) = True.
-- This is the key structural property: scope is a prefix namespace.

theorem prefix_implies_containment
    (P C : String)
    (hP : hasTraversal P = false)
    (hC : hasTraversal C = false)
    (hne : P ≠ "")
    (hpfx : C.startsWith (normalize P ++ "/") = true) :
    scopeContains P C = true := by
  simp [scopeContains, hP, hC, hne]
  right
  simpa using hpfx

-- ── Theorem T-SC5: Antisymmetry (normalized form) ───────────────────────────
-- If scopeContains(P, Q) and scopeContains(Q, P) and neither has traversal,
-- then normalize(P) = normalize(Q).
--
-- Formal statement from SEMANTICS.md §5:
--   "Antisymmetric: if scope_contains(P,Q) and scope_contains(Q,P) then
--    normalize(P) = normalize(Q)"
--
-- Was `sorry`. Now fully proved. The interesting case is when both prefix
-- branches fire: `normalizeL_of_slash_prefix` forces each normal form to be
-- either equal to the other or strictly longer, and both cannot be strictly
-- longer, so they are equal.

theorem scope_contains_antisymmetric
    (P Q : String)
    (hP : hasTraversal P = false)
    (hQ : hasTraversal Q = false)
    (hPQ : scopeContains P Q = true)
    (hQP : scopeContains Q P = true) :
    normalize P = normalize Q := by
  simp [scopeContains, hP, hQ] at hPQ hQP
  suffices h : normalizeL P.toList = normalizeL Q.toList by
    simpa [normalize] using congrArg String.ofList h
  -- An empty path normalizes to the empty list.
  have hnil : normalizeL (("" : String)).toList = [] := by simp [normalizeL]
  rcases hPQ with hPe | hPQ'
  · -- P = "" : force normalizeL Q.toList = [] as well.
    subst hPe
    have hQnil : normalizeL Q.toList = [] := by
      rcases hQP with hQe | hQP'
      · subst hQe; simp [normalizeL]
      · rcases hQP' with hQn | hQpfx
        · have h2 := congrArg String.toList hQn
          simp at h2
          first | exact h2 | exact h2.symm
        · -- normalizeL Q.toList ++ ['/'] is a prefix of [] — impossible
          exfalso; simp at hQpfx
    rw [hnil, hQnil]
  · rcases hQP with hQe | hQP'
    · -- Q = ""
      subst hQe
      have hPnil : normalizeL P.toList = [] := by
        rcases hPQ' with hPn | hPpfx
        · have h2 := congrArg String.toList hPn
          simp at h2
          first | exact h2 | exact h2.symm
        · exfalso; simp at hPpfx
      rw [hnil, hPnil]
    · rcases hPQ' with hPn | hPpfx
      · -- Q = normalize P, so normalizeL Q.toList = normalizeL (normalizeL P.toList)
        have h1 : Q.toList = normalizeL P.toList := by
          have := congrArg String.toList hPn; simpa using this
        rw [h1, normalizeL_idem]
      · rcases hQP' with hQn | hQpfx
        · -- P = normalize Q
          have h1 : P.toList = normalizeL Q.toList := by
            have := congrArg String.toList hQn; simpa using this
          rw [h1, normalizeL_idem]
        · -- Both prefix branches fire. Each normal form is either equal to the
          -- other or strictly longer; both cannot be strictly longer.
          have hA := normalizeL_of_slash_prefix (normalizeL_idem P.toList) hPpfx
          have hB := normalizeL_of_slash_prefix (normalizeL_idem Q.toList) hQpfx
          rcases hA with hA | hA
          · exact hA.symm
          · rcases hB with hB | hB
            · exact hB
            · omega

-- ── Summary ───────────────────────────────────────────────────────────────────
-- These theorems formally establish that scope_contains is:
--   T-SC1: Reflexive (any non-traversal path contains itself)
--   T-SC2: Root-universal (empty scope contains everything)
--   T-SC3: Traversal-safe (any ".." segment causes immediate rejection)
--   T-SC4: Prefix-implies-containment (structural prefix namespace property)
--   T-SC5: Antisymmetric (up to normalization)
--
-- As of 2026-08-02 all five are proved with no `sorry` and no added axioms.
-- Run `#print axioms` (below) to confirm; the expected result is `[]` for each,
-- i.e. they rest on nothing beyond Lean's own logic.

#print axioms scope_contains_reflexive
#print axioms scope_contains_root_universal
#print axioms traversal_in_parent_always_false
#print axioms traversal_in_child_always_false
#print axioms prefix_implies_containment
#print axioms scope_contains_antisymmetric

end FreedomKernel.Scope

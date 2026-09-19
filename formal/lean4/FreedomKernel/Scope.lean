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
-- Build: cd formal/lean4/FreedomKernel && lake build
--
-- 2026-09-16 rewrite: every operation here (split, normalize, endsWith,
-- prefix check) is defined directly over `List Char`, not
-- `String.splitOn`/`String.endsWith`/`String.startsWith`. Those String
-- methods go through byte-position `Substring` internals this Lean
-- toolchain has no lemma library for without Mathlib ("stdlib +
-- cryptography only" -- see AXIOMATIC_FOUNDATION.md), confirmed by direct
-- inspection of the toolchain source (no `Init/Data/String/Lemmas.lean`-
-- equivalent file exists). `List` operations reduce cleanly under `decide`
-- and have real lemma support (`List.isPrefixOf_iff_prefix`,
-- `List.IsPrefix.length_le`, `List.dropWhile_cons_of_pos/neg`, ...), so
-- this file proves the properties the spec above states, genuinely.
-- See DECISIONS.md for how this was found -- the aggregator's `lake build`
-- target was never wired up, so this file (and the whole library) had
-- never actually been checked before this fix, despite CI reporting green.
--
-- All 5 theorems in this file (T-SC1..T-SC5) are proved with zero `sorry`
-- as of 2026-09-16 -- including antisymmetry (T-SC5), whose last 2 gaps
-- ("crossed prefix ordering" sub-cases) closed via `crossed_contradiction`.

namespace FreedomKernel.Scope

-- ── Split, over List Char ─────────────────────────────────────────────────

-- Matches Python's `str.split(sep)` exactly (checked by #eval against
-- "a/b/../c" -> [a,b,..,c], "" -> [""], "/a" -> ["",a], "a/" -> [a,""]):
-- always at least one element, a run of `sep` produces an empty segment.
def splitOnChar (sep : Char) : List Char → List (List Char)
  | [] => [[]]
  | c :: cs =>
    let rest := splitOnChar sep cs
    if c = sep then [] :: rest
    else
      match rest with
      | r :: rs => (c :: r) :: rs
      | [] => [[c]] -- unreachable: splitOnChar always returns a nonempty list

theorem splitOnChar_ne_nil (sep : Char) (l : List Char) :
    splitOnChar sep l ≠ [] := by
  induction l with
  | nil => simp [splitOnChar]
  | cons c cs ih =>
    simp only [splitOnChar]
    split
    · simp
    · cases hrest : splitOnChar sep cs with
      | nil => exact absurd hrest ih
      | cons r rs => simp

-- ── Definitions ───────────────────────────────────────────────────────────────

def hasTraversalL (chars : List Char) : Bool :=
  (splitOnChar '/' chars).contains ['.', '.']

def hasTraversal (path : String) : Bool :=
  hasTraversalL path.data

-- Normalize: strip trailing "/" characters. Non-recursive
-- (`List.dropWhile` on the reversed list removes every trailing match in
-- one pass).
def normalizeL (chars : List Char) : List Char :=
  chars.reverse.dropWhile (· == '/') |>.reverse

def normalize (path : String) : String :=
  String.mk (normalizeL path.data)

-- List-level replacement for `path.endsWith "/"`, avoiding `Substring`
-- entirely: a nonempty list ends with '/' iff its head, reversed, is '/'.
def endsWithSlashL (chars : List Char) : Bool :=
  match chars.reverse with
  | '/' :: _ => true
  | _ => false

def scopeContainsL (P C : List Char) : Bool :=
  if hasTraversalL P || hasTraversalL C then false
  else if P == [] then true
  else
    let n := normalizeL P
    C == n || (n ++ ['/']).isPrefixOf C

def scopeContains (P C : String) : Bool :=
  scopeContainsL P.data C.data

-- ── Shared lemmas ─────────────────────────────────────────────────────────

theorem contains_false_not_mem {α : Type} [BEq α] [LawfulBEq α] (l : List α) (x : α)
    (h : l.contains x = false) : ¬ x ∈ l := by
  intro hmem
  have := List.elem_eq_true_of_mem hmem
  simp [List.contains] at h
  exact absurd this (by simp [h])

theorem normalizeL_no_trailing (chars : List Char) (h : endsWithSlashL chars = false) :
    normalizeL chars = chars := by
  unfold normalizeL
  cases hr : chars.reverse with
  | nil =>
      have : chars = [] := by
        have := congrArg List.reverse hr
        simpa using this
      simp [this]
  | cons c cs =>
      have hne : (c == '/') = false := by
        simp only [endsWithSlashL, hr] at h
        have hc : c ≠ '/' := by intro hc; subst hc; simp at h
        simpa using hc
      simp [List.dropWhile, hne]
      have hdata : chars = cs.reverse ++ [c] := by
        have := congrArg List.reverse hr
        simpa using this
      simp [hdata]

-- `List.dropWhile`'s defining property made explicit: its result's head (if
-- any) never satisfies the predicate. Not in the standard library under a
-- findable name (checked); proved here from the recursive equations
-- directly, once.
theorem dropWhile_head_fails (p : Char → Bool) (l : List Char) :
    ∀ c cs, l.dropWhile p = c :: cs → p c = false := by
  induction l with
  | nil => intro c cs h; simp at h
  | cons x xs ih =>
    intro c cs h
    by_cases hx : p x
    · rw [List.dropWhile_cons_of_pos hx] at h
      exact ih c cs h
    · rw [List.dropWhile_cons_of_neg (by simpa using hx)] at h
      simp at h
      obtain ⟨hxc, _⟩ := h
      subst hxc
      simpa using hx

-- normalizeL's own output never ends in '/' -- immediate from
-- `dropWhile_head_fails` applied to the definition -- so normalizing an
-- already-normalized path is a no-op.
theorem normalizeL_no_trailing_slash (chars : List Char) :
    endsWithSlashL (normalizeL chars) = false := by
  unfold endsWithSlashL normalizeL
  simp only [List.reverse_reverse]
  cases hr : chars.reverse.dropWhile (· == '/') with
  | nil => rfl
  | cons c cs =>
    have hc : c ≠ '/' := by
      have := dropWhile_head_fails (· == '/') chars.reverse c cs hr
      simpa using this
    split
    · next h => exact absurd (List.cons.inj h).1 hc
    · rfl

theorem normalizeL_idempotent (chars : List Char) :
    normalizeL (normalizeL chars) = normalizeL chars :=
  normalizeL_no_trailing (normalizeL chars) (normalizeL_no_trailing_slash chars)

-- `normalizeL X` is always a prefix of `X` (equal, if X has no trailing
-- slash; a genuine proper prefix via `trailing_slash_prefix` otherwise).
-- `trailing_slash_prefix` is defined further below, after this section, so
-- this helper is proved there instead and just declared here for use by
-- the antisymmetry proof -- see `normalizeL_prefix` near the bottom of this
-- file for the actual proof, kept next to the theorem it primarily serves.

-- If `a` is a prefix of `b ++ [x]` and no longer than `b`, it's a prefix of
-- `b` itself (the trailing `x` isn't part of what `a` reaches).
theorem prefix_of_append_of_le (a b : List Char) (x : Char)
    (h : a.IsPrefix (b ++ [x])) (hlen : a.length ≤ b.length) : a.IsPrefix b := by
  rw [List.prefix_iff_eq_take] at h ⊢
  rw [List.take_append_of_le_length hlen] at h
  exact h

-- Contrapositive-shaped: if `a` doesn't end with '/', it can't have exactly
-- `b`'s length plus the one appended '/' -- that would force `a = b ++ ['/']`
-- exactly, which does end with '/'.
theorem not_end_slash_of_prefix_append (a b : List Char)
    (h : a.IsPrefix (b ++ ['/'])) (hend : endsWithSlashL a = false) :
    a.length ≠ b.length + 1 := by
  intro hlen
  have heq : a = b ++ ['/'] := List.IsPrefix.eq_of_length h (by simpa using hlen)
  rw [heq] at hend
  simp only [endsWithSlashL] at hend
  simp at hend

-- The antisymmetry sub-case where each of normP/normQ is a prefix of the
-- *other's* one-slash extension (not the extension of a third list) closes
-- cleanly: two prefixes of nearly-equal length, ruling out the boundary
-- case (which would force one to literally end in '/', contradicting
-- `endP`/`endQ`), forces equal length and then equality.
theorem prefix_antisym_easy_branch (normP normQ : List Char)
    (endP : endsWithSlashL normP = false) (endQ : endsWithSlashL normQ = false)
    (hcP : normP.IsPrefix (normQ ++ ['/']))
    (hcQ : normQ.IsPrefix (normP ++ ['/'])) :
    normP = normQ := by
  have l1 := hcP.length_le
  have l2 := hcQ.length_le
  simp only [List.length_append, List.length_cons, List.length_nil] at l1 l2
  by_cases hle : normP.length ≤ normQ.length
  · by_cases hle2 : normQ.length ≤ normP.length
    · have hp1 : normP.IsPrefix normQ := prefix_of_append_of_le _ _ _ hcP hle
      exact List.IsPrefix.eq_of_length hp1 (Nat.le_antisymm hle hle2)
    · exact absurd (by omega) (not_end_slash_of_prefix_append normQ normP hcQ endQ)
  · exact absurd (by omega) (not_end_slash_of_prefix_append normP normQ hcP endP)

-- If chars ends with a slash, normalizeL chars ++ ['/'] is a prefix of
-- chars: chars = normalizeL(chars) ++ (one or more trailing slashes), and
-- one slash is a prefix of "one or more slashes". Proved by induction on
-- the reversed list, tracking exactly the run of trailing slashes dropWhile
-- removes.
-- Core recursive fact `trailing_slash_prefix` below needs: for any list
-- headed by '/', dropping-while-'/' then appending one '/' back gives a
-- prefix of the original (reversed) list. Proved by induction, tracking
-- `List.dropWhile`'s two defining equations (`_cons_of_pos`/`_cons_of_neg`)
-- directly rather than via `simp`, since `simp only [dropWhile_cons_of_pos
-- h] at ih ⊢` was found (empirically, see DECISIONS.md) to rewrite both
-- `ih` and the goal using the *same* instance of `h`, silently peeling one
-- extra layer of `ih` than intended -- `rw`, one call per intended peel, is
-- exact instead.
theorem dropWhile_slash_reverse_prefix (rest : List Char) :
    ((('/' : Char) :: rest).dropWhile (· == '/')).reverse ++ ['/'] <+:
      (('/' : Char) :: rest).reverse := by
  induction rest with
  | nil => decide
  | cons c2 rest2 ih =>
    have hslash : (fun x => x == '/') '/' = true := by decide
    by_cases hc2 : c2 == '/'
    · have hc2' : c2 = '/' := by simpa using hc2
      subst hc2'
      rw [List.dropWhile_cons_of_pos (p := fun x => x == '/') hc2] at ih
      rw [List.dropWhile_cons_of_pos (p := fun x => x == '/') hslash,
          List.dropWhile_cons_of_pos (p := fun x => x == '/') hc2]
      obtain ⟨t, ht⟩ := ih
      refine ⟨t ++ ['/'], ?_⟩
      rw [← List.append_assoc, ht]
      simp
    · rw [List.dropWhile_cons_of_pos (p := fun x => x == '/') hslash,
          List.dropWhile_cons_of_neg (p := fun x => x == '/') hc2]
      exact ⟨[], by simp⟩

theorem trailing_slash_prefix (chars : List Char) (h : endsWithSlashL chars = true) :
    (normalizeL chars ++ ['/']).isPrefixOf chars = true := by
  unfold normalizeL
  rw [List.isPrefixOf_iff_prefix]
  cases hr : chars.reverse with
  | nil =>
      simp only [endsWithSlashL, hr] at h
      exact absurd h (by decide)
  | cons c cs =>
    have hc : c = '/' := by
      simp only [endsWithSlashL, hr] at h
      by_cases heq : c = '/'
      · exact heq
      · exact absurd h (by simp [heq])
    subst hc
    have heq : chars = (('/' : Char) :: cs).reverse := by
      rw [← hr, List.reverse_reverse]
    rw [heq]
    exact dropWhile_slash_reverse_prefix cs

-- ── Antisymmetry's remaining "crossed" branches ──────────────────────────
-- What `dropWhile` strips off the end is *only* '/' characters (mirrors
-- `dropWhile_head_fails` -- that lemma says the first surviving character
-- isn't '/'; this one says every stripped character *is*), so `chars`
-- decomposes as its normalized form plus a run of trailing slashes.
theorem takeWhile_slash_eq_replicate (l : List Char) :
    ∃ n, l.takeWhile (fun c => c == '/') = List.replicate n '/' := by
  induction l with
  | nil => exact ⟨0, rfl⟩
  | cons x xs ih =>
    obtain ⟨n, hn⟩ := ih
    simp only [List.takeWhile]
    split
    · next hx =>
      have hx' : x = '/' := by simpa using hx
      exact ⟨n + 1, by rw [hx', hn]; rfl⟩
    · exact ⟨0, rfl⟩

theorem normalizeL_slash_suffix (chars : List Char) :
    ∃ n, chars = normalizeL chars ++ List.replicate n '/' := by
  obtain ⟨n, hn⟩ := takeWhile_slash_eq_replicate chars.reverse
  refine ⟨n, ?_⟩
  have heq : chars.reverse = chars.reverse.takeWhile (fun c => c == '/') ++ chars.reverse.dropWhile (fun c => c == '/') :=
    (List.takeWhile_append_dropWhile ..).symm
  rw [hn] at heq
  have hrev := congrArg List.reverse heq
  rw [List.reverse_append, List.reverse_replicate, List.reverse_reverse] at hrev
  unfold normalizeL
  exact hrev

-- A prefix of an all-'/' list is itself all '/' (of its own length).
theorem prefix_replicate_eq (X : List Char) (n : Nat) (c : Char) (h : X <+: List.replicate n c) :
    X = List.replicate X.length c := by
  obtain ⟨t, ht⟩ := h
  have hlen : X.length ≤ n := by
    have := congrArg List.length ht
    simp at this
    omega
  calc X = (List.replicate n c).take X.length := by rw [← ht]; simp
    _ = List.replicate (min X.length n) c := List.take_replicate ..
    _ = List.replicate X.length c := by rw [Nat.min_eq_left hlen]

-- Cancel a common prefix from both sides of a `<+:`.
theorem append_prefix_cancel (l A B : List Char) (h : l ++ A <+: l ++ B) : A <+: B := by
  induction l with
  | nil => simpa using h
  | cons x xs ih =>
    apply ih
    obtain ⟨t, ht⟩ := h
    refine ⟨t, ?_⟩
    have h2 : x :: (xs ++ A ++ t) = x :: (xs ++ B) := by
      simpa [List.append_assoc] using ht
    exact (List.cons.inj h2).2

theorem endsWithSlash_of_replicate_suffix (X : List Char) (j : Nat) (hj : j ≥ 1) :
    endsWithSlashL (X ++ List.replicate j '/') = true := by
  obtain ⟨j', rfl⟩ := Nat.exists_eq_succ_of_ne_zero (by omega : j ≠ 0)
  unfold endsWithSlashL
  rw [List.reverse_append, List.reverse_replicate]
  rfl

theorem append_right_cancel_slash (A B : List Char) (h : A ++ ['/'] = B ++ ['/']) : A = B := by
  have hlen : A.length = B.length := by
    have := congrArg List.length h
    simpa using this
  have hA : A = (A ++ ['/']).take A.length := by simp
  have hB : B = (B ++ ['/']).take B.length := by simp
  rw [hA, hB, h, hlen]

theorem replicate_succ_right (n : Nat) (c : Char) : List.replicate (n+1) c = List.replicate n c ++ [c] :=
  calc List.replicate (n+1) c
      = (List.replicate (n+1) c).reverse := (List.reverse_replicate _ _).symm
    _ = (c :: List.replicate n c).reverse := by rw [List.replicate_succ]
    _ = (List.replicate n c).reverse ++ [c] := by rw [List.reverse_cons]
    _ = List.replicate n c ++ [c] := by rw [List.reverse_replicate]

-- The actual "crossed ordering" closer: if `normQ ++ ['/']` is a prefix of
-- `normP` (so `normP` already reaches one level past `normQ`), that's
-- incompatible with `normP ++ ['/']` *also* being a prefix of `Ydata` where
-- `Ydata` itself is `normQ` plus nothing but trailing slashes -- the extra
-- level in `normP` would have to be a non-'/' character sitting inside a
-- region of `Ydata` that's provably all '/'. Concretely: cancel the shared
-- `normQ` prefix, use `prefix_replicate_eq` to show the remainder actually
-- *is* an all-'/' run, then peel it back onto `normP` itself -- which then
-- provably ends in '/', contradicting `endP`.
theorem crossed_contradiction (normP normQ Ydata : List Char) (m : Nat)
    (endP : endsWithSlashL normP = false)
    (hcP : normQ ++ ['/'] <+: normP)
    (hPQ : normP ++ ['/'] <+: Ydata)
    (hYeq : Ydata = normQ ++ List.replicate m '/') : False := by
  obtain ⟨rest, hrest⟩ := hcP
  have step1 : normP ++ ['/'] = normQ ++ (['/'] ++ rest ++ ['/']) := by
    rw [← hrest]; simp [List.append_assoc]
  rw [hYeq, step1] at hPQ
  have hcancel := append_prefix_cancel normQ _ _ hPQ
  have heqX := prefix_replicate_eq _ _ _ hcancel
  have hgeq2 : (['/'] ++ rest ++ ['/']).length ≥ 2 := by simp
  obtain ⟨j', hj'⟩ : ∃ j', (['/'] ++ rest ++ ['/']).length = j' + 1 :=
    ⟨(['/'] ++ rest ++ ['/']).length - 1, by omega⟩
  have hj'pos : j' ≥ 1 := by omega
  rw [hj', replicate_succ_right] at heqX
  have heqFinal := append_right_cancel_slash _ _ heqX
  have hnormP : normP = normQ ++ List.replicate j' '/' := by
    rw [← hrest, List.append_assoc, heqFinal]
  rw [hnormP] at endP
  rw [endsWithSlash_of_replicate_suffix normQ j' hj'pos] at endP
  exact absurd endP (by simp)

-- ── Theorem T-SC1: Reflexivity ────────────────────────────────────────────────
-- scope_contains(P, P) is True for all paths without traversal segments.

theorem scope_contains_reflexive (P : String) (h : hasTraversal P = false) :
    scopeContains P P = true := by
  simp only [hasTraversal] at h
  simp [scopeContains, scopeContainsL, h]
  by_cases hempty : P.data = []
  · exact Or.inl hempty
  · by_cases hslash : endsWithSlashL P.data
    · exact Or.inr (Or.inr ((List.isPrefixOf_iff_prefix).mp (trailing_slash_prefix P.data hslash)))
    · refine Or.inr (Or.inl ?_)
      simp only [Bool.not_eq_true] at hslash
      exact (normalizeL_no_trailing P.data hslash).symm ▸ (by simp)

-- ── Theorem T-SC2: Root scope contains everything ────────────────────────────
-- scope_contains("", C) is True for all C without traversal.

theorem scope_contains_root_universal (C : String) (h : hasTraversal C = false) :
    scopeContains "" C = true := by
  unfold scopeContains hasTraversal at *
  simp [scopeContainsL, hasTraversalL, splitOnChar, h]
  exact contains_false_not_mem _ _ h

-- ── Theorem T-SC3: Traversal paths always rejected ──────────────────────────
-- Security relevance: ".." sequences are never normalized away; they are
-- structurally rejected. Normalizing untrusted paths is an attack surface
-- (see SEMANTICS.md §5 "Path traversal" note).

theorem traversal_in_parent_always_false (P C : String) (h : hasTraversal P = true) :
    scopeContains P C = false := by
  unfold scopeContains hasTraversal at *
  simp [scopeContainsL, h]

theorem traversal_in_child_always_false (P C : String) (h : hasTraversal C = true) :
    scopeContains P C = false := by
  unfold scopeContains hasTraversal at *
  simp [scopeContainsL, h]

-- ── Theorem T-SC4: Prefix implies containment ────────────────────────────────
-- If C starts with normalize(P) ++ "/" and neither has traversal,
-- then scopeContains(P, C) = True. Scope is a prefix namespace.

theorem prefix_implies_containment
    (P C : String)
    (hP : hasTraversal P = false)
    (hC : hasTraversal C = false)
    (hne : P ≠ "")
    (hpfx : (normalizeL P.data ++ ['/']).isPrefixOf C.data = true) :
    scopeContains P C = true := by
  unfold scopeContains hasTraversal at *
  simp only [scopeContainsL, hP, hC, Bool.or_self, Bool.false_eq_true, if_false]
  have hpne : P.data ≠ [] := fun he => hne (String.ext (by simpa using he))
  simp [hpne, hpfx]

-- ── Theorem T-SC5: Antisymmetry (normalized form) ───────────────────────────
-- If scope_contains(P, Q) and scope_contains(Q, P) and neither has
-- traversal, then normalize(P) = normalize(Q).

theorem scope_contains_antisymmetric
    (P Q : String)
    (hP : hasTraversal P = false)
    (hQ : hasTraversal Q = false)
    (hPQ : scopeContains P Q = true)
    (hQP : scopeContains Q P = true) :
    normalize P = normalize Q := by
  simp only [hasTraversal] at hP hQ
  simp [scopeContains, scopeContainsL, hP, hQ] at hPQ hQP
  by_cases hp : P.data = []
  · by_cases hq : Q.data = []
    · simp [normalize, normalizeL, hp, hq]
    · -- P = "": scope_contains(Q, P) with P.data = [] forces either
      -- normalizeL Q.data ++ ['/'] to be a prefix of [] (impossible, it's
      -- nonempty -- simp_all discharges that disjunct on its own) or
      -- Q.data = normalizeL Q.data... no: the surviving disjunct is
      -- normalizeL Q.data = [] itself (e.g. Q = "/", which really does
      -- normalize to "" same as P) -- not a contradiction, the genuine
      -- conclusion. `simp_all` correctly narrowed to exactly that.
      simp_all [normalize, normalizeL]
  · by_cases hq : Q.data = []
    · -- Symmetric to the previous case.
      simp_all [normalize, normalizeL]
    · -- Neither empty: both scopeContainsL calls already reduced (by the
      -- broad `simp` above) to "exact match or proper prefix" shape.
      -- The exact-match sub-cases close via `normalizeL_idempotent`
      -- (applying `normalizeL` twice is a no-op, since its own output
      -- never ends in '/'). The "both proper prefixes" sub-case needed
      -- `List.prefix_or_prefix_of_prefix` (two prefixes of one list are
      -- comparable) rather than the pure-length argument first tried here
      -- -- `omega` found a real counterexample to that, see DECISIONS.md.
      -- `prefix_antisym_easy_branch` below closes the case where that
      -- comparison lines the two prefixes up against each *other's*
      -- extension directly; the two remaining "crossed" orderings close via
      -- `crossed_contradiction` (defined above, before T-SC1) -- each one
      -- turns out to be impossible outright, not just hard to compare by
      -- length: cancel the shared normalized prefix and what's left has to
      -- be a run of pure '/' characters (`prefix_replicate_eq`), which
      -- forces the "crossed" side to end in '/', contradicting `endP`/
      -- `endQ`. Zero `sorry` in this file as of 2026-09-16.
      -- `hPQ`/`hQP` still carry their original `P.data = [] ∨ ...` /
      -- `Q.data = [] ∨ ...` shape from the very first `simp` above (that
      -- one ran before this `by_cases` split); drop the now-impossible
      -- empty disjunct with `hp`/`hq` before using either.
      simp only [hp, hq, false_or] at hPQ hQP
      have hbP : normalizeL P.data <+: P.data := by
        by_cases he : endsWithSlashL P.data
        · exact (List.prefix_append (normalizeL P.data) ['/']).trans
            ((List.isPrefixOf_iff_prefix).mp (trailing_slash_prefix P.data he))
        · simp only [Bool.not_eq_true] at he
          rw [normalizeL_no_trailing P.data he]
          exact List.prefix_refl P.data
      have hbQ : normalizeL Q.data <+: Q.data := by
        by_cases he : endsWithSlashL Q.data
        · exact (List.prefix_append (normalizeL Q.data) ['/']).trans
            ((List.isPrefixOf_iff_prefix).mp (trailing_slash_prefix Q.data he))
        · simp only [Bool.not_eq_true] at he
          rw [normalizeL_no_trailing Q.data he]
          exact List.prefix_refl Q.data
      have endP : endsWithSlashL (normalizeL P.data) = false := normalizeL_no_trailing_slash P.data
      have endQ : endsWithSlashL (normalizeL Q.data) = false := normalizeL_no_trailing_slash Q.data
      obtain ⟨k, hPeq⟩ := normalizeL_slash_suffix P.data
      obtain ⟨m, hQeq⟩ := normalizeL_slash_suffix Q.data
      have hcore : normalizeL P.data = normalizeL Q.data := by
        rcases hPQ with hPQ | hPQ
        · rw [hPQ]; exact (normalizeL_idempotent P.data).symm
        rcases hQP with hQP | hQP
        · rw [hQP]; exact normalizeL_idempotent Q.data
        · rcases List.prefix_or_prefix_of_prefix hbP hQP with hcP | hcP
          · rcases List.prefix_or_prefix_of_prefix hbQ hPQ with hcQ | hcQ
            · exact prefix_antisym_easy_branch _ _ endP endQ hcP hcQ
            · exact (crossed_contradiction (normalizeL Q.data) (normalizeL P.data) P.data k
                endQ hcQ hQP hPeq).elim
          · exact (crossed_contradiction (normalizeL P.data) (normalizeL Q.data) Q.data m
              endP hcP hPQ hQeq).elim
      simp [normalize, hcore]

end FreedomKernel.Scope

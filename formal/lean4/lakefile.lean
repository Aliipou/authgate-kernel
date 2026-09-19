import Lake
open Lake DSL

package «authgate» where

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.32.2"

@[default_target]
lean_lib «Authgate» where
  roots := #[`Authgate.Core, `Authgate.Invariants, `Authgate.Proofs]

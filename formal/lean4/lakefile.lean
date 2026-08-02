import Lake
open Lake DSL

package «authgate-kernel» where

/-- The self-contained core library: depends only on Lean 4 core (no Mathlib).
    There is no `FreedomKernel.lean` root module, so the library is declared by
    globbing the submodules rather than by `roots := #[`FreedomKernel]`, which
    silently matched nothing and made `lake build` a no-op ("Nothing to build"). -/
@[default_target]
lean_lib «FreedomKernel» where
  globs := #[.submodules `FreedomKernel]

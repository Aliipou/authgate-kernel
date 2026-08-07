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

/-- `formal/FreedomKernel.lean` is a standalone root module living one directory
    above this package, so the glob above cannot see it. It was therefore never
    compiled by `lake build`, even though it carries the strongest results in the
    development (`ownerless_machine_blocked`, `public_read_permitted`,
    `sovereignty_always_blocks`). A second library rooted at it puts those
    theorems under the build instead of leaving them unverified. -/
@[default_target]
lean_lib «FreedomKernelRoot» where
  srcDir := ".."
  roots := #[`FreedomKernel]

import Lake
open Lake DSL

package «FreedomKernel» where
  name := `FreedomKernel

-- Every .lean file here sits flat in this package's root directory
-- (Scope.lean, TCB.lean, ... alongside FreedomKernel.lean, not nested under
-- a FreedomKernel/ subdirectory), so each is listed explicitly as its own
-- root module. `roots := #[`FreedomKernel]` alone (the previous config)
-- silently excluded all the others from the library's module set -- Lake
-- had nothing to build them as part of -- which combined with no
-- `@[default_target]` meant `lake build` succeeded by building nothing.
@[default_target]
lean_lib «FreedomKernel» where
  roots := #[`FreedomKernel, `Scope, `TCB, `Temporal, `MultiAgent, `Incompleteness, `OntologicalRoot]

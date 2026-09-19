-- Root module for Lake build of FreedomKernel formal artifacts.
--
-- Import paths are bare module names, not `FreedomKernel.X`: every .lean
-- file here sits flat in this package's root directory (not nested under a
-- FreedomKernel/ subdirectory), so that's what Lake's module resolution
-- actually needs, regardless of the `namespace FreedomKernel.X` each file
-- declares internally -- import-path resolution and internal namespacing
-- are independent in Lean. See DECISIONS.md for how this was found: the
-- dotted form silently built nothing (no `@[default_target]` was even set,
-- so `lake build` had no target to fail on) rather than erroring, so this
-- had never actually been checked by the CI job that reports it green.
import Scope
import TCB
import Temporal
import MultiAgent
import Incompleteness
import OntologicalRoot

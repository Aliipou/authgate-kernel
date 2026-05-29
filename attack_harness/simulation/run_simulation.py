"""
AuthGate Adversarial Simulation Runner.

Usage:
    cd attack_harness
    python simulation/run_simulation.py
    python simulation/run_simulation.py --verbose
    python simulation/run_simulation.py --class "AT-1"
"""

from __future__ import annotations

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulation.engine import SimulationEngine, Outcome


def main() -> int:
    parser = argparse.ArgumentParser(description="AuthGate adversarial simulation")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print all scenario names and outcomes")
    parser.add_argument("--class", dest="filter_class", metavar="CLASS",
                        help="Run only scenarios matching this attack class substring")
    args = parser.parse_args()

    engine = SimulationEngine()

    if args.filter_class:
        engine._specs = [s for s in engine._specs
                         if args.filter_class.lower() in s.attack_class.lower() or
                            args.filter_class.lower() in s.name.lower()]

    print(f"AuthGate Adversarial Simulation — {engine.scenario_count} scenarios")
    print("=" * 60)

    summary = engine.run()

    if args.verbose:
        by_class: dict[str, list] = {}
        for spec in engine._specs:
            by_class.setdefault(spec.attack_class, []).append(spec)

        for cls, specs in by_class.items():
            print(f"\n  {cls}")
            for spec in specs:
                result = spec.execute()
                marker = {"PASS": "  PASS", "KNOWN-GAP": "  GAP ", "FAIL": "  FAIL"}[result.outcome.value]
                print(f"    {marker}  {result.name}")
                if result.detail:
                    print(f"           {result.detail}")

    print()
    print(f"  Total:      {summary.total}")
    print(f"  PASS:       {summary.passed}")
    print(f"  KNOWN-GAP:  {summary.known_gaps}")
    print(f"  FAIL:       {summary.failed}")

    if summary.failures:
        print()
        print("FAILURES (security regressions):")
        for r in summary.failures:
            print(f"  [{r.attack_class}] {r.name}")
            if r.detail:
                print(f"      {r.detail}")
        print()
        print("RESULT: FAIL — security properties violated")
        return 1

    print()
    print(f"RESULT: PASS — {summary.passed} properties hold, {summary.known_gaps} known gap(s) documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())

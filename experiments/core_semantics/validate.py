"""Reproducible IR-only validation; does not declare production migration ready."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import tracemalloc

from experiments.core_semantics.engine import Program, Solver
from experiments.core_semantics.scenarios import call_chain, recursive_program, witnesses
from experiments.core_semantics.test_engine import concrete_union, generated_programs, observed
from experiments.core_semantics.oracle import Concrete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    files = sorted(Path(__file__).resolve().parent.glob("*.py"))
    hashes = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    manifest = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    report = {"scope": "independent executable IR specification; not production scanner acceptance",
              "python": platform.python_version(), "source_manifest": hashes, "source_sha256": manifest,
              "witnesses": {}, "generated": {}, "cost": [], "budgets": {}}
    for name, document in witnesses().items():
        program = Program(document)
        result = Solver(program).run()
        expected = concrete_union(document)
        actual = observed(result)
        report["witnesses"][name] = {**result.report(), "expected": {k: sorted(v) for k, v in expected.items()},
                                      "matches_concrete_traces": actual == expected}
        assert result.status == "fixed_point" and actual == expected, name
    generated = list(generated_programs())
    for index, document in enumerate(generated):
        result = Solver(Program(document)).run()
        assert result.status == "fixed_point" and observed(result) == Concrete(document).run(), index
    report["generated"] = {"seed": 17, "programs": len(generated), "exact_matches": len(generated),
                           "scope": "straight-line field reads/writes and definite aliases; no frontend"}
    for objects in (False, True):
        for size in (8, 32, 128):
            program = Program(call_chain(size, objects))
            tracemalloc.start()
            result = Solver(program).run()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            assert result.status == "fixed_point" and result.findings == {}
            if not objects:
                assert result.stats["transfers"] <= 4 * size + 4
            report["cost"].append({"calls": size, "objects": size if objects else 0,
                                   "python_traced_peak_bytes": peak, **result.stats})
    for name, budget in (("transfers", {"max_steps": 1}), ("invocations", {"max_invocations": 1}),
                         ("wall_time", {"max_seconds": 0})):
        result = Solver(Program(recursive_program()), **budget).run()
        assert result.status == "incomplete_budget"
        report["budgets"][name] = result.report()
    report["gates"] = {"ir_semantics": True, "independent_finite_trace_differential": True,
                       "recursive_fixed_point_witness": True, "explicit_conservative_budget_exit": True,
                       "call_block_worklist_cost": True, "moonbit_frontend_adapter": False,
                       "real_corpus_cost": False, "production_migration_approved": False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"ir_witnesses": len(report["witnesses"]), "generated": report["generated"],
                      "cost": report["cost"], "gates": report["gates"]}, indent=2))


if __name__ == "__main__":
    main()

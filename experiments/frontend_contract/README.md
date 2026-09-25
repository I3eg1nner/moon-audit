# Official frontend capability probe

This experiment checks what the pinned MoonBit CLI actually returns. It does not
implement source lowering, type inference, pointer analysis, or a production
frontend, and it does not import the current scanner or the IR solver.

Use the selected toolchain's environment, then run from the repository root:

```bash
python3 experiments/frontend_contract/probe.py \
  --work-dir /tmp/moon-audit-frontend-probe-new \
  --report /tmp/moon-audit-frontend-probe.json
```

The work directory must not exist. `--moon /absolute/path/to/moon` can select a
binary, but its matching `moonc`/standard library must also be available in the
environment. The run first performs `moon check --target native`, then queries
that unchanged source snapshot using `--no-check`. All arguments, return codes,
stdout/stderr, fixture text, hashes and elapsed times are retained in the report.

Fourteen queries exercise direct calls, type display, fields, shadowing, two
packages with the same function name, a concrete method, generic constraints,
callbacks, defaults, errors and references. Query positions are fixture-authored;
this experiment does not yet discover or classify every call in a program.

Exit codes:

- `0`: all stated query expectations match; this still does not approve a frontend.
- `1`: a query expectation or immutable-source check fails; inspect the report.
- `2`: the fixture does not compile; no semantic queries are attempted.

With moon `0.1.20260920` / moonc `v0.10.14`, the recorded run exits **1**:
13/14 query expectations match. Generic `value.render()` resolves to its
`T : Render` constraint location instead of the expected trait declaration.
This is a limitation of the proposed extraction contract, not a claim that the
compiler's IDE navigation is defective. The mismatching expectation is retained.

`gen-symbols` produces 20 entries across the three fixture packages, including
trait implementation metadata. Its `tag` repeats across declarations and is not
a unique identity. The observed index has no expression types, statement bodies,
argument binding, CFG or heap effects. `hover` returns presentation text, and
`peek-def` returns declaration locations, not complete runtime targets.

The report always marks `solver_input_ready=false`: this probe cannot yet produce
complete input for `experiments/core_semantics`.

See the [G0 findings and next contract](../../docs/frontend-contract-2026-09-23.md)
and [recorded run](../../docs/metrics/frontend-capability-2026-09-23.json).

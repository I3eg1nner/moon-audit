# Core semantics specification

This isolated Python prototype tests a replacement semantic chain. It does not
import the MoonBit AST scanner, call its fallback paths, or run in production.

- `engine.py`: immutable IR input, canonical objects, one heap domain, explicit
  call bindings, block-level dependency worklist, normal/exception exits.
- `oracle.py`: independent concrete executor with fresh runtime objects.
- `scenarios.py`: inspectable IR witnesses and cost workloads.
- `test_engine.py`: differential, alias, order, exception, cache and budget gates.
- `validate.py`: reproducible machine-readable evidence.

From the repository root:

```bash
python3 -m unittest experiments.core_semantics.test_engine -v
python3 -m experiments.core_semantics.validate --report /tmp/core-semantics.json
```

The program model deliberately excludes dynamic dispatch, default arguments,
closures, arrays, FFI, concurrency and source lowering. Unsupported opcodes and
incomplete bindings fail explicitly. `fixed_point` means analysis convergence;
`incomplete_budget` produces a conservative result and is not a successful
semantic acceptance result.

The result cache belongs only to this specification. Its key includes immutable
IR, bindings, argument values, input heap and policy/budgets. It is not the
production incremental cache.

The bounded source domain avoids growing symbolic field paths. Full input heaps
still create storage and hashing costs: IR semantics passing is insufficient to
approve production migration. See the [architecture decision and gates](../../docs/core-semantics-validation-2026-09-22.md).

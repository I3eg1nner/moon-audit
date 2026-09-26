# Compilation context evidence — 2026-09-26

These records distinguish official CLI observations, **pre-change analyzer counterexamples**, and the bounded post-change compatibility acceptance below. They do not claim full semantic support for historical MoonBit versions.

## Evidence

- `official-plan-observations.json`: two pinned toolchains' argument arity, command/role counts from actual projects, and a small reproducible `source = "src"` fixture with native/js plans.
- `baseline-role-counterexamples.json`: the baseline analyzer SHA, fixed mocket fingerprints, complete fixture bodies and compact actual outcomes.
- `binding-transport-observations.json`: exact-location query transport probes and bounded concurrency measurements on one Linux host.
- `compatibility-acceptance.json`: post-change binary SHA, twelve backend/version cases, unchanged historical project results, and independent official-plan identity comparisons.

All project source modifications used isolated temporary fixtures. Machine-specific paths are replaced with explicit placeholders; full process traces and large logs are omitted. A raw-plan hash identifies the original unnormalized local transcript, not the normalized excerpt.

## What the compiler actually selects

Both tested generations emit `-whitebox-test` and `-blackbox-test`. An ordinary file can occur as production source, whitebox source and blackbox `-doctest-only` input. A package-name suffix cannot substitute for these flags. With module `audit/identity_probe` and `source = "src"`, `src/lib` is package `audit/identity_probe/lib`.

An input file is therefore distinct from its compilation context. Preserve the scanner's file union, but give production semantics only confirmed production inputs. Parse flag values by arity: warning values such as `-a` are values, not additional flags. Unknown flags or conflicting identities must not silently become production. `-pkg-sources` uses `package:path`; parse the known package prefix so Windows drive letters remain intact.

Input replacement (`-patch-file`, `-replace-name`, `-replace-content`) and standalone mode require separate handling. The existence of a compiler flag in the arity evidence does not imply analyzer support for its semantics. Historical plans omit modern `-pkg-type` and `-all-pkgs`.

File selection alone does not select AST items. The baseline incorrectly reports a production semantic finding for a callback inside an ordinary file's `test` block. Disabled `#cfg(false)` and `#cfg(target="js")` callbacks currently yield incomplete binding errors. Production item selection must exclude tests and explicitly handle conditional declarations; no condition interpretation is established by this experiment.

## Binding performance limits

The pinned current CLI resolves one location per query. Repeated `--loc` uses the final location; comma-separated locations fail, and `--stdio` is rejected. Calling `moon-ide` directly did not materially improve the observed warm-query latency. `--no-check` still invokes an incremental core check, according to a local process trace.

The historical toolchain offers `goto-definition`, not current exact-location `peek-def`. Its fuzzy name lookup is not an equivalent semantic fallback. Pin both `MOON_HOME` and `PATH` to avoid accidentally mixing toolchain components.

The 24-query experiment compared 1, 2, 4 and 8 workers. Results support retaining bounded concurrency; they do not establish a portable Windows speedup or justify a larger process limit. New caching would need complete source/dependency/configuration, compiler, module, target and role identity, plus snapshot revalidation.

## Reproduction and subsequent acceptance

To recreate official plans, materialize `module_fixture` from `official-plan-observations.json`, then run the selected toolchain with its matching `MOON_HOME` and `PATH`:

```sh
moon check --frozen --target native
moon check --frozen --target native --dry-run --verbose
moon check --frozen --target js
moon check --frozen --target js --dry-run --verbose
moonc check -help
```

The baseline callback bodies use the unchanged mocket fixture and model fingerprint checks in `scripts/native_semantic_test.py`. The analyzer command is:

```sh
moon-audit --analysis semantic --verify-project --semantic-scope mocket-get-callbacks \
  --project-toolchain "$CURRENT_TOOLCHAIN" --format json "$FIXTURE"
```

After producing a new binary, existing independent regressions can be run as follows. The matrix is **three toolchains × four backends = twelve cases**, not twelve versions. The following commands produced the compatibility acceptance record:

```sh
python3 scripts/native_version_matrix.py --scanner "$ANALYZER" \
  --toolchain "$TOOLCHAIN_20260904" --toolchain "$TOOLCHAIN_20260915" \
  --toolchain "$CURRENT_TOOLCHAIN" --output "$EVIDENCE/native-version-matrix.json"

python3 experiments/historical_project/verify.py --analyzer "$ANALYZER" \
  --work-dir "$HISTORICAL_CACHE" --scope-toolchain "$CURRENT_TOOLCHAIN" \
  --output "$EVIDENCE/historical"
```

The historical driver verifies pinned archive bytes, the unchanged 2025 quickcheck checkout and eight compiler-scope cases across two toolchains. Its success is not evidence that old toolchains support the current semantic binding protocol.

## Post-change compatibility result

The binary identified in `compatibility-acceptance.json` passed all twelve matrix cases and all eight historical/current scope regressions. An independent Python parser compared actual compiler plans against reported module name/root, package name/root, package kind, backend, role and each input mode: all eight scope cases and the historical project matched. Both toolchains distinguish production, whitebox and blackbox roles in the test fixture.

The unchanged 2025 quickcheck archive still selects 30 files and parses 22; eight known parser failures remain an explicit `scope_incomplete` result. Its 18 compilation units comprise nine production and nine blackbox units. All 55 archived files retained their pinned original bytes. This is compatibility and boundary validation, not new historical semantic support or a claim that the parser accepts the remaining eight files.

## Implementation and local acceptance

`compilation_units` records module, package, package kind, target, compiler role and each input mode. Semantic analysis accepts production source only; `source_units` and `function_units` map emitted IR back to those identities. Inline tests are skipped. Relevant conditional declarations, unrecognized/replacing compiler contexts and inputs outside the snapshot ledger explicitly remain incomplete. Syntax selection keeps its existing file union and policy.

Structural lowering now completes the callback/helper body before issuing its binding queries. Both the baseline and revised analyzer reject the same unsupported-If fixture. Binding queries dropped **256 → 1**; observed Linux invocation time was **59.751 → 1.449 seconds**. Cache/load differ, so the timing is an observation, not a portable speed guarantee. Supported bodies retain the same 256-query/4-worker/60-second ceilings; no new control-flow or heap semantics were added.

`local-acceptance.json` links compressed raw acceptance reports and their hashes. Seven new cases cover test isolation, complete identity mappings, disabled cfg entries, reached cfg helpers, structural rejection query cost, and resolution-stage shared-helper rollback. Existing semantic 16, cross-package 9 (including unchanged Luna runtime 15), and cmark 14 cases pass. Native delivery 37 includes the actual compiler accepting `source = "_build/source"` while the analyzer correctly reports its missing snapshot coverage. CLI 22 and process supervision 4 also pass. Unit counts are wasm/wasm-gc/js 93 each and native 103.

Independent review checked the implementation and found three boundary gaps, all fixed before acceptance: package-kind identity, dependency compiler-context validation and snapshot coverage. Generated public interfaces are refreshed. This milestone does not implement workspace aggregation, arbitrary external dependency summaries, or historical-toolchain semantic binding.

### Recheck recorded compilation identities independently

`check_plan_identity.py` reads an actual plan, the analyzer's JSON report and the original project directory. It uses the checked-in observed flag arity and compares every unit and input mode. It does not invoke Moon or modify the project. The configuration reader intentionally covers the JSON manifests and simple literal `name = "..."` assignments used here; it is not an independent implementation of arbitrary Moon configuration syntax. The recorded paths must still identify the original fixture directories on the current host.

```sh
python3 experiments/compilation_context/check_plan_identity.py \
  --plan "$EVIDENCE/historical/historical-plan.stdout" \
  --report "$EVIDENCE/historical/verified.stdout" \
  --project-root "$HISTORICAL_CACHE/project/quickcheck-04e4d54c0b3cb5a53f2c2530f7eadf546a903f60"

for generation in historical current; do
  for case in empty backend_package test_files policy_excluded; do
    python3 experiments/compilation_context/check_plan_identity.py \
      --plan "$EVIDENCE/historical/$generation-$case-plan.stdout" \
      --report "$EVIDENCE/historical/$generation-$case-scan.stdout" \
      --project-root "$HISTORICAL_CACHE/scope-fixtures/$generation/$case"
  done
done
```

These nine comparisons were rerun using the checked-in oracle and all passed. Empty fixtures correctly contain no project compilation units with source inputs.

# Pinned compatibility frontend

This is a minimal vendored subset of `moonbitlang/parser` 0.4.0 with the official 0.3.0 `Expr::Loop` and `TryOperatorKind::Question` representations restored. It is **not an official parser release**. Compatibility ID: `0.4.0+moon-audit-legacy.1`.

Production rule scanning, interpolation expansion and native semantic lowering consume these same AST types. The original registry parser remains available to the internal `frontend_export` executable as an independent current-syntax oracle; `frontend_export --compat FILE` exports the raw compatibility Handrolled AST for comparison (without interpolation expansion or yacc fallback).

## Intentional limits

- Lexical errors discarded during recovery remain errors in both parsers.
- Only Handrolled parsing gains the two legacy productions. MoonYacc remains the unchanged current-syntax fallback and can still reject mixed inputs that Handrolled cannot parse.
- Legacy nodes retain their own kinds, cases, labels and original locations. There is no source/token rewriting into modern constructs.
- Native security lowering explicitly rejects these unmodeled nodes. Parsing success does not imply dataflow support.
- Other historical/current gaps, including tuple-pattern `for ... in` and literate inputs, are not addressed here.

## Integrity and upgrades

`vendor.lock.json` records official archive URLs/hashes and exact upstream/current file hashes. `compat.patch` records every byte difference from the corresponding 0.4.0 files, including package relocation, omitted upstream test imports, and disabled yacc regeneration. The large generated yacc file is copied unchanged; users need no parser generator or Python step to compile the scanner.

Run after dependency resolution:

```sh
python scripts/check_frontend_vendor.py --upstream .mooncakes/moonbitlang/parser
```

For independent reproduction, verify the official 0.4.0 archive hash in the lock, copy only the listed files preserving their relative paths, and apply `compat.patch` with one leading path component stripped. The result must match every current file hash. Generated `pkg.generated.mbti` interfaces are produced by `moon info` and are not upstream source inputs.

Upgrades must preserve: unchanged AST/locations for previously accepted inputs, faithful legacy nodes, rejection of malformed inputs, stable findings on previously parsed files, explicit semantic incompleteness, and three-platform delivery. Keep the patch limited to evidenced grammar gaps. Do not silently regenerate tables, patch `.mooncakes`, or import unrelated old frontend code to make a sample pass.

See `LICENSE` and `NOTICE` for attribution and modifications. The binary distribution includes the license, notice, lock and patch.

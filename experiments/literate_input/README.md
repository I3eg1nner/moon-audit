# Literate MoonBit compiler oracle (2026-09-26)

This is a compiler behavior experiment, not a Markdown extractor implementation.
Only the two pinned toolchains below are characterized; no version transition boundary is inferred.

- current: `moonc v0.10.14+7d59c7ec9 (2026-09-18)`
- historical: `moonc v0.6.30+07d9d2445 (2025-10-30)`

`toolchains.json` records compiler binary SHA-256 and version output.
`results.json.gz` has 306 command observations (51 source cases × two toolchains × three modes).
**51 historical `syncheck` observations are unsupported-command results**, marked
`unsupported_command: true`; they provide no syntax evidence. The historical compiler lacks that subcommand.
`extended.json.gz` adds 128 `moonc check` observations. `roles.json.gz` adds 30 mode/package observations.
`*-package-plan.json.gz` and `*-package-actual.json.gz` record the package commands and output.
The three observation arrays total **464 records, with 51 excluded unsupported-command
records**; this is not a count of passing tests. The four package plan/actual records
are supplementary evidence. Source text and diagnostics are embedded in JSON, preserving CRLF and original line/column locations.
No API keys, repository `.env`, or network services were used.

## Findings

| Fence info | 2025 compiler | 2026 compiler |
| --- | --- | --- |
| `mbt`, `moonbit` | parse top-level declarations | ignore |
| `mbt check`, `moonbit check` | ignore | parse top-level declarations |
| `mbt test`, `moonbit test` | ignore | parse a statement/expression block with implicit test context |
| `mbt nocheck` | ignore | ignore |

This reversal means one hardcoded extraction policy cannot match both tested versions.
The second space-separated token selects current `check`/`test`: `mbt check extra`
is processed, `mbt nocheck check` is ignored, `mbt check,` is ignored, and
`mbt\tcheck` is ignored. Surrounding info whitespace is trimmed. These are observed
examples, not a claimed complete grammar.

Both tested generations recognize 3-or-more backtick fences and tilde fences,
0–3 leading spaces, simple blockquote containers, and unclosed fences through EOF.
Four leading spaces, inline fence-looking text, fences nested inside foreign-language
fences, and initial frontmatter change whether a would-be MoonBit block is visible.
Additional current-compiler probes establish correctly formed list and nested
blockquote containers and suppression inside HTML comments. A raw line search for
fence markers therefore does not define a faithful adapter.

Each selected top-level block is parsed independently: an opening function brace
in one block cannot be closed in the next. Complete declarations from separate
blocks share a package type-checking scope. `mbt test` needs a distinct block parser:
an expression statement is accepted there but rejected as a top-level declaration;
a literal `test { ... }` declaration has the converse parsing behavior.

Diagnostics retain original Markdown file coordinates. Two leading spaces and a
blockquote `> ` prefix both move the unknown identifier from column 17 to column 19.
CRLF retains line 4 / column 17 in the same probe. This requires a source map for
container-prefix removal, implicit test wrappers, and independent block parsing.

Both `moon check --dry-run` package plans place `.mbt.md` in a separate
`-blackbox-test` command and package name ending `_blackbox_test`; ordinary `.mbt`
production inputs are in their own command and appear under `-doctest-only` in the
blackbox command. A private production function is inaccessible from the active
literate block in each version. Thus input extension alone does not establish
production/test role, and a scope adapter should retain compiler command roles.

## Recommendation

Do not silently skip literate files, and do not claim compiler-compatible literate
support from a single Markdown regex. Report unsupported inputs and incomplete
coverage until their extraction contract is implemented and checked.

The preferred adapter is compiler-owned extraction with a stable interface returning
block role, content, original byte/line coordinates, and parse context. No such
public extraction API was established in this experiment. Do not claim it exists.

If that interface is unavailable, use explicit, tested frontend profiles tied to
compiler identities or a independently checked feature probe; an unknown version
must preserve uncertainty. A profile needs all of:

1. Markdown parsing behavior and active fence labels.
2. Independent top-level blocks versus implicit test blocks.
3. Production/blackbox command role and backend selection.
4. Source mapping for containers, Unicode, CRLF, and wrappers.
5. Differential tests against the selected compiler, including ignored negative
   controls and malformed input, before declaring scope complete.

A conservative subset can be a staged implementation, but unsupported Markdown
forms must produce incomplete coverage instead of falling back to raw AST parsing.
Do not expand a growing chain of Markdown special cases to compensate for a missing
input representation.

## Reproduce

Run with Python 3 and already installed fixed toolchains; the scripts do not download
or mutate the project under review. Output defaults to this `/tmp` experiment path.
Set the following environment variables to relocate inputs/output:

```sh
export CURRENT_MOON_HOME=/path/to/current/toolchain
export HISTORICAL_MOON_HOME=/path/to/historical/toolchain
export LITERATE_ORACLE_OUTPUT=/tmp/literate-oracle-rerun
python3 probe.py
python3 extended.py
python3 roles.py
```

Inspect recorded return codes and diagnostics; nonzero compiler results are intentional
negative controls. Case definitions are shared through normal imports from `cases.py`. Keep all
five Python files together. Every compiler command has a 30-second timeout; package
checks have a 90-second timeout. Timeouts abort the experiment instead of recording
a pass. JSON outputs are compressed with gzip; inspect them using Python `gzip.open`. The tools create temporary package build directories
inside `LITERATE_ORACLE_OUTPUT`. No repository build or production source is modified.

The committed gzip files preserve the original recorded JSON bytes. The delivered
scripts were refactored after recording to share case definitions, use portable PATH
separators, and bound subprocess duration. Their generated case names and source
contents were compared against every recorded source case.
